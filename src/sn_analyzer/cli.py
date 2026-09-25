"""Command-line entry point and pipeline coordinator for the network analyzer."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import sys
import threading
from typing import Any, ClassVar

import numpy as np

from .alerting.alert_manager import AlertManager, EvidencePcapExporter
from .alerting.sinks import AlertSink
from .config import AppSettings, ConfigError, load_settings
from .features.packet_features import FeatureExtractionError, FeatureExtractor
from .inference.engine import InferenceEngine
from .ingestion.base import PacketEnvelope, PacketSource
from .ingestion.live_capture import LiveCaptureError, LivePacketCapture, list_capture_interfaces
from .ingestion.pcap_reader import PcapFileSource
from .ingestion.stream_demux import (
    StreamDemultiplexer,
    StreamDemultiplexingError,
    StreamKey,
)
from .models.isolation_forest import IsolationForestModel
from .models.registry import AnomalyModel
from .storage.alert_repository import AlertRepository, SqliteAlertSink


@dataclass(slots=True)
class _FlowWindow:
    """Packets accumulated for a single flow before feature extraction."""

    packets: list[PacketEnvelope] = field(default_factory=list)
    started_at: datetime | None = None
    ended_at: datetime | None = None

    def add(self, envelope: PacketEnvelope) -> None:
        """Add one packet and maintain the true temporal bounds of the window."""
        captured_at = envelope.captured_at_utc
        self.packets.append(envelope)
        self.started_at = (
            captured_at if self.started_at is None else min(self.started_at, captured_at)
        )
        self.ended_at = (
            captured_at if self.ended_at is None else max(self.ended_at, captured_at)
        )


# How often (in packet time) ``process_packet`` scans for idle streams.  The scan
# is linear in the number of tracked streams, so running it for every packet
# would dominate CPU at high packet rates.
_EXPIRY_CHECK_INTERVAL = timedelta(seconds=1)


class AnalyzerService:
    """Coordinate packet ingestion, feature windows, ML inference, and alerts.

    When no fitted models are supplied, the first ``bootstrap_windows`` flow
    windows become the normal-traffic baseline for a local Isolation Forest.
    Baseline observations do not create alerts.  For real deployments, supply
    a pre-trained model produced from representative authorized traffic.

    All packet and window state is guarded by one re-entrant lock, so
    :meth:`process_packet`, :meth:`tick`, and status reads may be used from
    different threads (live capture runs a background ticker; a future API
    server will read status).
    """

    def __init__(
        self,
        *,
        models: Mapping[str, AnomalyModel] | None = None,
        model_weights: Mapping[str, float] | None = None,
        threshold: float = 0.80,
        evidence_directory: str | Path = "artifacts/evidence",
        window_packet_count: int = 50,
        window_duration: timedelta = timedelta(seconds=30),
        stream_idle_timeout: timedelta = timedelta(minutes=5),
        alert_cooldown: timedelta = timedelta(minutes=5),
        bootstrap_windows: int = 100,
        max_active_flows: int = 10_000,
        tick_interval: timedelta = timedelta(seconds=1),
        clock: Callable[[], datetime] | None = None,
        alert_sinks: Sequence[AlertSink] = (),
        model_save_path: str | Path | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """Instantiate all pipeline dependencies and validate runtime settings.

        Args:
            max_active_flows: Most flows tracked at once.  Beyond it the least
                recently active flow is scored early and dropped, keeping
                memory bounded during scans or floods.
            tick_interval: How often live capture runs idle housekeeping.
            clock: Time source for :meth:`tick`; defaults to the UTC wall clock.
            alert_sinks: Receivers, such as a database, of every alert created.
            model_save_path: Where to persist the model(s) once baseline
                training completes.  Ignored when ``models`` is supplied,
                because a pre-trained model never goes through baseline
                training in the first place.
        """
        if window_packet_count <= 0:
            raise ValueError("window_packet_count must be greater than zero")
        if window_duration <= timedelta(0):
            raise ValueError("window_duration must be greater than zero")
        if bootstrap_windows <= 0:
            raise ValueError("bootstrap_windows must be greater than zero")
        if max_active_flows <= 0:
            raise ValueError("max_active_flows must be greater than zero")
        if tick_interval <= timedelta(0):
            raise ValueError("tick_interval must be greater than zero")

        self._logger = logger or logging.getLogger(__name__)
        self._lock = threading.RLock()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._tick_interval = tick_interval
        self._last_expiry_check: datetime | None = None
        self._demultiplexer = StreamDemultiplexer(
            idle_timeout=stream_idle_timeout, max_streams=max_active_flows
        )
        self._feature_extractor = FeatureExtractor()
        self._models = dict(models) if models is not None else {
            "isolation_forest": IsolationForestModel(random_state=42)
        }
        self._model_weights = (
            dict(model_weights)
            if model_weights is not None
            else {name: 1.0 for name in self._models}
        )
        self._threshold = threshold
        self._engine = InferenceEngine(self._models, self._model_weights, threshold)
        self._alert_manager = AlertManager(
            EvidencePcapExporter(evidence_directory),
            cooldown=alert_cooldown,
            logger=self._logger,
            sinks=alert_sinks,
        )

        self._window_packet_count = window_packet_count
        self._window_duration = window_duration
        self._windows: dict[StreamKey, _FlowWindow] = {}
        self._bootstrap_required = models is None
        self._bootstrap_windows = bootstrap_windows
        self._baseline_feature_rows: list[np.ndarray] = []
        self._model_save_path = Path(model_save_path) if model_save_path is not None else None
        if self._model_save_path is not None and models is not None:
            self._logger.warning(
                "model_save_path is set but pre-trained models were supplied; "
                "baseline training never runs, so nothing will be saved to %s",
                self._model_save_path,
            )

    _MODEL_SAVE_PATH_UNSET: ClassVar[object] = object()
    """Sentinel default for ``from_settings``'s ``model_save_path``.

    Distinguishes "the caller didn't pass this at all, fall back to
    ``settings.model.save_path``" from "the caller explicitly passed
    ``None``, meaning don't save" -- the latter is how the HTTP API overrides
    a configured save path for one session.
    """

    @classmethod
    def from_settings(
        cls,
        settings: AppSettings,
        *,
        models: Mapping[str, AnomalyModel] | None = None,
        alert_sinks: Sequence[AlertSink] = (),
        model_save_path: str | Path | None | object = _MODEL_SAVE_PATH_UNSET,
        logger: logging.Logger | None = None,
    ) -> "AnalyzerService":
        """Build a service from validated configuration.

        Args:
            settings: Resolved configuration; see :func:`sn_analyzer.config.load_settings`.
            models: Pre-trained models.  When omitted, a baseline is learned
                from the first ``analysis.bootstrap_windows`` windows.
            alert_sinks: Receivers of every alert created.
            model_save_path: Overrides ``settings.model.save_path`` for this
                service only, already resolved against ``model.model_dir`` by
                the caller.  Left unset, ``settings.model.save_path`` is used
                (resolved here).  Pass ``None`` explicitly to disable saving
                regardless of what the configuration says.
            logger: Logger to use instead of this module's default.
        """
        analysis = settings.analysis
        if model_save_path is cls._MODEL_SAVE_PATH_UNSET:
            model_save_path = (
                settings.model.resolve_model(str(settings.model.save_path))
                if settings.model.save_path is not None
                else None
            )
        return cls(
            models=models,
            threshold=analysis.threshold,
            evidence_directory=settings.storage.evidence_dir,
            window_packet_count=analysis.window_packets,
            window_duration=analysis.window_duration,
            stream_idle_timeout=analysis.stream_idle_timeout,
            alert_cooldown=analysis.alert_cooldown,
            bootstrap_windows=analysis.bootstrap_windows,
            max_active_flows=analysis.max_active_flows,
            tick_interval=analysis.tick_interval,
            alert_sinks=alert_sinks,
            model_save_path=model_save_path,  # type: ignore[arg-type]
            logger=logger,
        )

    @property
    def engine(self) -> InferenceEngine:
        """Return the active inference engine for status inspection."""
        return self._engine

    @property
    def is_ready(self) -> bool:
        """Whether the service is evaluating observations instead of warming up."""
        return not self._bootstrap_required

    def run(self, source: PacketSource) -> None:
        """Consume a packet source until exhaustion, shutdown, or Ctrl+C.

        Partial flow windows are processed during shutdown.  Unsupported packet
        formats and failed feature extractions are logged and skipped so one
        malformed packet cannot terminate an authorized monitoring session.
        """
        if not isinstance(source, PacketSource):
            raise TypeError("source must implement PacketSource")

        # A live source can go quiet, and then no packet arrives to trigger
        # housekeeping, so a background ticker calls tick() on a timer.  Offline
        # replay is driven purely by packet timestamps and needs no ticker.
        stop_ticker = threading.Event()
        ticker: threading.Thread | None = None
        if source.is_live:
            ticker = threading.Thread(
                target=self._tick_loop,
                args=(stop_ticker,),
                name="sn-analyzer-tick",
                daemon=True,
            )
            ticker.start()

        try:
            for envelope in source.packets():
                self.process_packet(envelope)
        except KeyboardInterrupt:
            self._logger.info("Shutdown requested; stopping packet capture")
            source.stop()
        finally:
            stop_ticker.set()
            if ticker is not None:
                ticker.join(timeout=5.0)
            self._flush_all_windows()
            source.stop()

    def tick(self, now: datetime | None = None) -> int:
        """Run time-based housekeeping that does not depend on new packets.

        Flushes every window that has been open for at least ``window_duration``
        and expires streams idle for ``stream_idle_timeout``, so a flow that goes
        quiet is still scored promptly.  ``now`` defaults to the service clock.
        Only call it with wall-clock time for live traffic; timestamps from an
        old capture would make every window look stale.

        Returns:
            The number of windows flushed.
        """
        current = now if now is not None else self._clock()
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("now must include timezone information")
        current = current.astimezone(timezone.utc)

        flushed = 0
        with self._lock:
            stale = [
                key
                for key, window in self._windows.items()
                if window.started_at is not None
                and current - window.started_at >= self._window_duration
            ]
            for stream_key in stale:
                self._flush_window(stream_key)
                flushed += 1

            for stream_key in self._demultiplexer.expire_idle_streams(current):
                if stream_key in self._windows:
                    self._flush_window(stream_key)
                    flushed += 1
        return flushed

    def _tick_loop(self, stop: threading.Event) -> None:
        """Call :meth:`tick` periodically until ``stop`` is set."""
        interval = self._tick_interval.total_seconds()
        while not stop.wait(interval):
            try:
                self.tick()
            except Exception:
                # The ticker must outlive a single failure (for example a model
                # error), otherwise quiet flows would silently stop being scored.
                self._logger.exception("Idle tick failed; will retry next interval")

    @property
    def active_flow_count(self) -> int:
        """Return how many flows are currently tracked."""
        return self._demultiplexer.active_stream_count

    @property
    def evicted_flow_count(self) -> int:
        """Return how many flows were scored early because the flow cap was hit."""
        return self._demultiplexer.evicted_total

    def process_packet(self, envelope: PacketEnvelope) -> None:
        """Add one packet to its flow and process any completed windows."""
        with self._lock:
            self._process_packet(envelope)

    def _process_packet(self, envelope: PacketEnvelope) -> None:
        """Implementation of :meth:`process_packet`; the caller holds the lock."""
        try:
            stream_key = self._demultiplexer.add(envelope)
        except StreamDemultiplexingError as exc:
            self._logger.debug(
                "Skipped unsupported packet sequence_id=%s: %s",
                envelope.sequence_id,
                exc,
            )
            return
        except Exception:
            # Safety net: the demultiplexer normalizes expected failures, but a
            # long-running monitor must survive an unforeseen per-packet bug.
            # The traceback is kept so the defect stays visible in the logs.
            self._logger.warning(
                "Skipped packet sequence_id=%s after unexpected demultiplexing error",
                envelope.sequence_id,
                exc_info=True,
            )
            return

        # A new flow at the cap pushed out the least recently active one; score
        # its partial window now so its packets are neither lost nor retained.
        self._flush_evicted_flows()

        window = self._windows.setdefault(stream_key, _FlowWindow())
        window.add(envelope)

        if self._window_is_complete(window):
            self._flush_window(stream_key)

        observed_at = envelope.captured_at_utc
        if (
            self._last_expiry_check is None
            or abs(observed_at - self._last_expiry_check) >= _EXPIRY_CHECK_INTERVAL
        ):
            self._last_expiry_check = observed_at
            for expired_stream in self._demultiplexer.expire_idle_streams(observed_at):
                self._flush_window(expired_stream)

    def _flush_evicted_flows(self) -> None:
        """Flush windows of flows the demultiplexer evicted to honor its cap."""
        evicted = self._demultiplexer.drain_evicted()
        if not evicted:
            return

        total = self._demultiplexer.evicted_total
        # Under a scan this happens per packet, so log the first event and then
        # only every 1000th to keep the log readable.
        if total == len(evicted) or total % 1000 < len(evicted):
            self._logger.warning(
                "Flow cap of %s reached; %d flow(s) scored early and dropped "
                "(%d evicted in total)",
                self._demultiplexer.max_streams,
                len(evicted),
                total,
            )
        for stream_key in evicted:
            self._flush_window(stream_key)

    def _window_is_complete(self, window: _FlowWindow) -> bool:
        """Return whether packet-count or elapsed-time windowing has triggered."""
        if len(window.packets) >= self._window_packet_count:
            return True
        if window.started_at is None or window.ended_at is None:
            return False
        return window.ended_at - window.started_at >= self._window_duration

    def _flush_window(self, stream_key: StreamKey) -> None:
        """Extract, score, and alert one completed stream window when possible."""
        window = self._windows.pop(stream_key, None)
        if window is None or not window.packets or window.ended_at is None:
            return

        try:
            observation = self._feature_extractor.extract_window_features(
                stream_key, window.packets, window.ended_at
            )
        except FeatureExtractionError as exc:
            self._logger.warning(
                "Feature extraction failed for stream %s: %s", stream_key, exc
            )
            return

        if self._bootstrap_required:
            self._add_baseline_observation(observation.values)
            return

        try:
            result = self._engine.evaluate(observation)
            self._alert_manager.handle(result, window.packets)
        except Exception:
            self._logger.exception("Inference failed for stream %s", stream_key)

    def _add_baseline_observation(self, values: np.ndarray) -> None:
        """Collect baseline windows and fit models once enough observations exist."""
        self._baseline_feature_rows.append(np.array(values, dtype=float, copy=True))
        collected = len(self._baseline_feature_rows)
        if collected < self._bootstrap_windows:
            self._logger.debug(
                "Baseline warm-up progress: %d/%d windows",
                collected,
                self._bootstrap_windows,
            )
            return

        baseline = np.vstack(self._baseline_feature_rows)
        try:
            for model in self._models.values():
                model.fit(baseline)
            self._engine = InferenceEngine(
                self._models,
                self._model_weights,
                self._threshold,
                baseline_mean=baseline.mean(axis=0),
                baseline_variance=baseline.var(axis=0),
            )
        except Exception:
            self._logger.exception("Unable to fit anomaly models from baseline traffic")
            raise
        else:
            self._bootstrap_required = False
            self._baseline_feature_rows.clear()
            self._logger.info(
                "Baseline training complete; anomaly inference is now active"
            )
            self._save_models()

    def _save_models(self) -> None:
        """Persist every fitted model to ``model_save_path``, if configured.

        A single model is written directly to the configured path.  With more
        than one registered model, each is written beside it with its name
        appended (``path.stem.<name><path.suffix>``), since a model artifact
        holds exactly one model.  A save failure is logged, not raised: it must
        not stop the pipeline that just finished training and is now ready to
        score live traffic.
        """
        if self._model_save_path is None:
            return
        try:
            if len(self._models) == 1:
                ((_, model),) = self._models.items()
                model.save(str(self._model_save_path))
            else:
                for name, model in self._models.items():
                    destination = self._model_save_path.with_name(
                        f"{self._model_save_path.stem}.{name}"
                        f"{self._model_save_path.suffix}"
                    )
                    model.save(str(destination))
        except Exception:
            self._logger.exception(
                "Failed to save trained model to %s", self._model_save_path
            )
        else:
            self._logger.info("Saved trained model to %s", self._model_save_path)

    def _flush_all_windows(self) -> None:
        """Process every partial window retained during normal operation."""
        with self._lock:
            for stream_key in list(self._windows):
                self._flush_window(stream_key)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Options that map to a configuration setting default to ``None`` instead of a
    value, so they override the config file and environment only when the user
    actually types them.  The real defaults live in :mod:`sn_analyzer.config`.
    """
    parser = argparse.ArgumentParser(description="Smart Network Anomaly Analyzer")
    parser.add_argument(
        "--config", help="YAML configuration file (or set the SN_CONFIG_FILE variable)"
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List capture interfaces Scapy can see, then exit",
    )
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("--pcap", help="Path to a PCAP or PCAPNG file")
    source_group.add_argument("--interface", help="Authorized interface to capture")
    parser.add_argument("--bpf", help="Optional BPF filter for live capture")
    parser.add_argument(
        "--promiscuous",
        action="store_true",
        default=None,
        help="Request promiscuous mode for live capture when authorized",
    )
    parser.add_argument("--model", help="Path to a trusted saved Isolation Forest artifact")
    parser.add_argument(
        "--save-model",
        help="Save the model trained from baseline traffic to this path "
        "(ignored when --model loads a pre-trained one)",
    )
    parser.add_argument("--threshold", type=float)
    parser.add_argument("--window-packets", type=int)
    parser.add_argument("--window-seconds", type=float)
    parser.add_argument("--bootstrap-windows", type=int)
    parser.add_argument(
        "--max-flows",
        type=int,
        help="Most flows tracked at once; the least active is scored early beyond it",
    )
    parser.add_argument(
        "--tick-seconds",
        type=float,
        help="Interval of live-capture housekeeping that flushes quiet flows",
    )
    parser.add_argument("--evidence-dir", help="Directory for evidence PCAP files")
    database_group = parser.add_mutually_exclusive_group()
    database_group.add_argument("--db-path", help="SQLite file that stores alert history")
    database_group.add_argument(
        "--no-db", action="store_true", help="Do not store alert history"
    )
    parser.add_argument("--verbose", action="store_true", help="Log at DEBUG level")
    return parser


# (settings section, settings field, argparse attribute) for every overridable option.
_OVERRIDE_MAP: tuple[tuple[str, str, str], ...] = (
    ("capture", "interface", "interface"),
    ("capture", "bpf_filter", "bpf"),
    ("capture", "promiscuous", "promiscuous"),
    ("model", "path", "model"),
    ("model", "save_path", "save_model"),
    ("analysis", "threshold", "threshold"),
    ("analysis", "window_packets", "window_packets"),
    ("analysis", "window_seconds", "window_seconds"),
    ("analysis", "bootstrap_windows", "bootstrap_windows"),
    ("analysis", "max_active_flows", "max_flows"),
    ("analysis", "tick_seconds", "tick_seconds"),
    ("storage", "evidence_dir", "evidence_dir"),
    ("storage", "database_path", "db_path"),
)


def _settings_overrides(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    """Translate the command-line options the user typed into settings overrides."""
    overrides: dict[str, dict[str, Any]] = {}
    for section, name, attribute in _OVERRIDE_MAP:
        value = getattr(args, attribute)
        if value is not None:
            overrides.setdefault(section, {})[name] = value
    if args.no_db:
        overrides.setdefault("storage", {})["database_path"] = None
    if args.verbose:
        overrides["logging"] = {"level": "DEBUG"}
    return overrides


def _print_capture_interfaces() -> int:
    """Print every capture interface Scapy can see and return a process code."""
    try:
        interfaces = list_capture_interfaces()
    except LiveCaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not interfaces:
        print("No capture interfaces were found.")
        return 0

    name_width = max(len(interface.name) for interface in interfaces)
    for interface in interfaces:
        address = interface.ip_address or "-"
        line = f"{interface.name.ljust(name_width)}  {address:<15}  {interface.description}"
        print(line.rstrip())
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the analyzer from command-line arguments and return a process code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_interfaces:
        return _print_capture_interfaces()

    if args.pcap and (args.bpf or args.promiscuous):
        parser.error("--bpf and --promiscuous are supported only with --interface")
    try:
        settings = load_settings(args.config, _settings_overrides(args))
    except ConfigError as exc:
        parser.error(str(exc))
    if not args.pcap and settings.capture.interface is None:
        parser.error(
            "choose a packet source: --pcap FILE, --interface NAME, "
            "or capture.interface in the config file"
        )

    logging.basicConfig(
        level=getattr(logging, settings.logging.level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger(__name__)

    try:
        with ExitStack() as resources:
            sinks: list[AlertSink] = []
            if settings.storage.database_path is not None:
                repository = resources.enter_context(
                    AlertRepository(settings.storage.database_path)
                )
                sinks.append(SqliteAlertSink(repository))
                logger.info("Recording alerts in %s", repository.location)

            models: dict[str, AnomalyModel] | None = None
            if settings.model.path is not None:
                model_path = settings.model.resolve_model(str(settings.model.path))
                models = {"isolation_forest": IsolationForestModel.load(str(model_path))}

            service = AnalyzerService.from_settings(
                settings, models=models, alert_sinks=sinks, logger=logger
            )
            source: PacketSource
            if args.pcap:
                source = PcapFileSource(settings.capture.resolve_pcap(args.pcap))
            else:
                source = LivePacketCapture(
                    settings.capture.interface,
                    bpf_filter=settings.capture.bpf_filter,
                    promiscuous=settings.capture.promiscuous,
                )
            service.run(source)
        return 0
    except KeyboardInterrupt:
        logger.info("Shutdown complete")
        return 130
    except Exception:
        logger.exception("Analyzer terminated with an error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
