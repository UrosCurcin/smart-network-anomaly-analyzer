"""Anomaly alert creation, deduplication, logging, and PCAP evidence export."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import tempfile
from threading import RLock
from typing import Literal
from uuid import uuid4

from ..inference.engine import InferenceResult
from ..ingestion.base import PacketEnvelope
from ..ingestion.stream_demux import StreamKey
from .sinks import AlertSink


class EvidenceExportError(RuntimeError):
    """Raised when anomalous packets cannot be written to an evidence PCAP."""


Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class Alert:
    """Immutable security event generated from an anomalous inference result.

    Attributes:
        alert_id: Unique identifier for this alert instance.
        created_at: Timezone-aware UTC time at which the alert was created.
        severity: Risk tier derived from the ensemble anomaly score.
        result: Original inference result that triggered this event.
        suspicious_ips: Canonical IP addresses associated with the anomalous flow.
        evidence_pcap_path: Absolute PCAP path containing contributing packets,
            or ``None`` when no evidence was retained or export failed.
        acknowledged: Whether an analyst has marked this alert as observed.
            Always ``False`` for a newly created alert; set later through
            :meth:`sn_analyzer.storage.alert_repository.AlertRepository.set_acknowledged`.
    """

    alert_id: str
    created_at: datetime
    severity: Severity
    result: InferenceResult
    suspicious_ips: tuple[str, ...]
    evidence_pcap_path: str | None = None
    acknowledged: bool = False

    def __post_init__(self) -> None:
        """Validate required alert fields and normalize the creation timestamp."""
        if not self.alert_id or not self.alert_id.strip():
            raise ValueError("alert_id must be a non-empty string")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if self.severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("severity must be low, medium, high, or critical")
        if not isinstance(self.result, InferenceResult):
            raise TypeError("result must be an InferenceResult")
        if not self.suspicious_ips:
            raise ValueError("suspicious_ips must contain at least one address")
        if self.evidence_pcap_path is not None and not self.evidence_pcap_path.strip():
            raise ValueError("evidence_pcap_path must be non-empty when provided")
        if not isinstance(self.acknowledged, bool):
            raise TypeError("acknowledged must be a bool")

        object.__setattr__(self, "created_at", self.created_at.astimezone(timezone.utc))
        object.__setattr__(self, "suspicious_ips", tuple(self.suspicious_ips))


class EvidencePcapExporter:
    """Persist exact contributing packets into an isolated PCAP artifact."""

    def __init__(self, evidence_directory: str | Path) -> None:
        """Configure the directory used exclusively for generated evidence PCAPs."""
        directory = Path(evidence_directory).expanduser()
        if not str(directory):
            raise ValueError("evidence_directory must be non-empty")
        self._evidence_directory = directory.resolve()

    @property
    def evidence_directory(self) -> Path:
        """Return the resolved directory where evidence artifacts are written."""
        return self._evidence_directory

    def export(self, alert_id: str, packets: Sequence[PacketEnvelope]) -> str:
        """Write packet payloads to ``<alert_id>.pcap`` and return its path.

        The file is first written beside its final destination and then atomically
        moved into place.  Only trusted processes should be granted access to
        evidence files because packet payloads can contain sensitive data.
        """
        if not alert_id or not alert_id.strip():
            raise ValueError("alert_id must be a non-empty string")
        if not packets:
            raise EvidenceExportError("cannot export an empty packet collection")
        if any(not isinstance(envelope, PacketEnvelope) for envelope in packets):
            raise TypeError("packets must contain only PacketEnvelope instances")

        try:
            from scapy.utils import wrpcap
        except ImportError as exc:
            raise EvidenceExportError(
                "Scapy is required to export evidence PCAP files; install the "
                "project's packet-capture dependency."
            ) from exc

        self._evidence_directory.mkdir(parents=True, exist_ok=True)
        safe_alert_id = self._safe_filename_component(alert_id)
        destination = (self._evidence_directory / f"{safe_alert_id}.pcap").resolve()
        if destination.parent != self._evidence_directory:
            raise EvidenceExportError("evidence destination escaped its configured directory")

        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self._evidence_directory,
                prefix=f".{safe_alert_id}.",
                suffix=".partial.pcap",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)

            wrpcap(str(temporary_path), [envelope.packet for envelope in packets])
            temporary_path.replace(destination)
            return str(destination)
        except EvidenceExportError:
            raise
        except Exception as exc:
            raise EvidenceExportError(
                f"failed to export evidence PCAP for alert {alert_id!r}"
            ) from exc
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _safe_filename_component(value: str) -> str:
        """Restrict alert IDs to a portable filename component."""
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        sanitized = "".join(character for character in value if character in allowed)
        if not sanitized:
            raise ValueError("alert_id does not contain a safe filename component")
        return sanitized


class AlertManager:
    """Create non-duplicative alerts and retain packet evidence for incidents."""

    def __init__(
        self,
        exporter: EvidencePcapExporter,
        *,
        cooldown: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] | None = None,
        logger: logging.Logger | None = None,
        sinks: Sequence[AlertSink] = (),
    ) -> None:
        """Configure evidence export, a duplicate-alert cooldown, and alert sinks.

        Args:
            sinks: Receivers (for example a database) that are handed every
                alert that is created, after it has been logged.
        """
        if cooldown <= timedelta(0):
            raise ValueError("cooldown must be greater than zero")
        if any(not isinstance(sink, AlertSink) for sink in sinks):
            raise TypeError("sinks must contain only AlertSink instances")
        self._sinks = tuple(sinks)
        self._exporter = exporter
        self._cooldown = cooldown
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._logger = logger or logging.getLogger(__name__)
        self._last_alert_at: dict[StreamKey, datetime] = {}
        self._lock = RLock()

    def should_suppress(self, result: InferenceResult, now: datetime | None = None) -> bool:
        """Return whether the result's flow remains inside its alert cooldown."""
        timestamp = self._normalized_now(now)
        stream_key = result.observation.stream_key
        with self._lock:
            last_alert = self._last_alert_at.get(stream_key)
            if last_alert is None:
                return False
            elapsed = timestamp - last_alert
            return timedelta(0) <= elapsed < self._cooldown

    def handle(
        self,
        result: InferenceResult,
        packets: Sequence[PacketEnvelope],
    ) -> Alert | None:
        """Create an alert, export PCAP evidence, and log an anomalous result.

        Returns ``None`` for ordinary observations or a suppressed duplicate.
        An evidence-export failure does not discard the security alert; the
        returned alert instead has ``evidence_pcap_path=None`` and the failure
        is logged with traceback information.
        """
        if not isinstance(result, InferenceResult):
            raise TypeError("result must be an InferenceResult")
        if not result.is_anomalous:
            return None

        created_at = self._normalized_now(None)
        stream_key = result.observation.stream_key
        with self._lock:
            last_alert = self._last_alert_at.get(stream_key)
            elapsed = created_at - last_alert if last_alert is not None else None
            if elapsed is not None and timedelta(0) <= elapsed < self._cooldown:
                self._logger.debug(
                    "Suppressed duplicate network anomaly for stream %s", stream_key
                )
                return None
            # Reserve the cooldown before exporting so concurrent workers cannot
            # create duplicate alerts while writing evidence.
            self._last_alert_at[stream_key] = created_at

        alert_id = str(uuid4())
        evidence_packets = self._evidence_packets(result, packets)
        evidence_path: str | None = None
        if evidence_packets:
            try:
                evidence_path = self._exporter.export(alert_id, evidence_packets)
            except Exception:
                self._logger.exception(
                    "Failed to export PCAP evidence for alert %s", alert_id
                )
        else:
            self._logger.warning(
                "No contributing packets were supplied for anomalous alert %s", alert_id
            )

        alert = Alert(
            alert_id=alert_id,
            created_at=created_at,
            severity=self._severity_for(result.anomaly_score),
            result=result,
            suspicious_ips=self._suspicious_ips(stream_key),
            evidence_pcap_path=evidence_path,
        )
        self._logger.warning(
            "Network anomaly alert=%s severity=%s score=%.4f stream=%s "
            "suspicious_ips=%s evidence_pcap=%s",
            alert.alert_id,
            alert.severity,
            alert.result.anomaly_score,
            stream_key,
            ",".join(alert.suspicious_ips),
            alert.evidence_pcap_path or "unavailable",
        )
        self._publish(alert)
        return alert

    def _publish(self, alert: Alert) -> None:
        """Hand an alert to every sink, isolating each sink's failures."""
        for sink in self._sinks:
            try:
                sink.publish(alert)
            except Exception:
                # A broken sink (full disk, locked database) must neither lose
                # the alert for the other sinks nor stop live monitoring.
                self._logger.exception(
                    "Alert sink %s failed to publish alert %s",
                    type(sink).__name__,
                    alert.alert_id,
                )

    def _normalized_now(self, supplied_time: datetime | None) -> datetime:
        """Return a timezone-aware UTC time from an override or injected clock."""
        current_time = supplied_time if supplied_time is not None else self._clock()
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return current_time.astimezone(timezone.utc)

    @staticmethod
    def _evidence_packets(
        result: InferenceResult, packets: Sequence[PacketEnvelope]
    ) -> list[PacketEnvelope]:
        """Select only packet envelopes used to build the triggering feature vector."""
        packet_ids = set(result.observation.packet_ids)
        if not packet_ids:
            return []
        selected: list[PacketEnvelope] = []
        for envelope in packets:
            if not isinstance(envelope, PacketEnvelope):
                raise TypeError("packets must contain only PacketEnvelope instances")
            if envelope.sequence_id in packet_ids:
                selected.append(envelope)
        return selected

    @staticmethod
    def _suspicious_ips(stream_key: StreamKey) -> tuple[str, ...]:
        """Return distinct endpoint addresses associated with the anomalous flow."""
        return tuple(dict.fromkeys((stream_key.endpoint_a.address, stream_key.endpoint_b.address)))

    @staticmethod
    def _severity_for(score: float) -> Severity:
        """Map normalized anomaly score to an operational severity tier."""
        if score >= 0.95:
            return "critical"
        if score >= 0.85:
            return "high"
        if score >= 0.70:
            return "medium"
        return "low"
