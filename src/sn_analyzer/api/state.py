"""Framework-free application state for the HTTP API.

Everything in this module is plain Python: no FastAPI import anywhere.  The
API layer (``app.py`` and ``routers/``) is a thin translation from HTTP to
these classes, which keeps the actual behavior unit-testable without a web
framework or a running server.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from pathlib import Path
import threading
from typing import Literal

from ..cli import AnalyzerService
from ..config import AppSettings
from ..ingestion.base import PacketSource
from ..ingestion.live_capture import LivePacketCapture
from ..ingestion.pcap_reader import PcapFileSource
from ..models.isolation_forest import IsolationForestModel
from ..models.registry import AnomalyModel
from ..storage.alert_repository import AlertRepository, SqliteAlertSink

CaptureStateName = Literal["idle", "running", "stopping", "failed"]


class CaptureAlreadyRunningError(RuntimeError):
    """Raised when starting capture while a session is already active."""


@dataclass(frozen=True, slots=True)
class CaptureStatus:
    """Point-in-time snapshot of the capture session, for status reporting."""

    state: CaptureStateName
    source: str | None
    started_at: datetime | None
    error: str | None
    is_ready: bool
    active_flow_count: int
    evicted_flow_count: int
    threshold: float
    model_save_path: str | None


class CaptureController:
    """Owns the one background capture session the API can start and stop.

    ``AnalyzerService`` is already safe to use from multiple threads (see its
    own docstring: it has an internal lock, and live capture already runs a
    background ticker thread against it).  The lock here is a different,
    narrower one: it only protects this controller's own start/stop
    bookkeeping (so two near-simultaneous "start" requests can't both
    succeed), not packet processing itself.
    """

    def __init__(
        self,
        settings: AppSettings,
        repository: AlertRepository,
        *,
        logger: logging.Logger | None = None,
    ) -> None:
        """Bind the controller to configuration and the shared alert database.

        Args:
            settings: Resolved configuration used for every session started
                through this controller, unless a request overrides a field.
            repository: Open alert database.  Every session's alerts are
                written here, so alerts are queryable immediately, regardless
                of which capture session produced them.
        """
        self._settings = settings
        self._repository = repository
        self._logger = logger or logging.getLogger(__name__)
        self._lock = threading.Lock()
        self._service: AnalyzerService | None = None
        self._source: PacketSource | None = None
        self._thread: threading.Thread | None = None
        self._state: CaptureStateName = "idle"
        self._source_label: str | None = None
        self._started_at: datetime | None = None
        self._error: str | None = None
        self._model_save_path: Path | None = None

    def start(
        self,
        *,
        interface: str | None = None,
        pcap: str | None = None,
        bpf: str | None = None,
        promiscuous: bool | None = None,
        model_path: str | None = None,
        model_save_path: str | None = None,
    ) -> None:
        """Start one capture session in a background thread.

        A request-supplied field overrides the matching ``capture.*``/
        ``model.*`` setting for this one session only; the stored
        configuration is never changed. Supplying ``pcap`` always means a
        PCAP replay, regardless of what ``capture.interface`` is set to.

        Args:
            model_path: Load a trusted saved model for this session instead
                of training a new baseline; overrides ``model.path``. A bare
                filename resolves under ``model.model_dir``.
            model_save_path: Save the trained model once baseline training
                completes this session; overrides ``model.save_path``.
                Ignored when a model is loaded (via ``model_path`` or
                ``model.path``), since no baseline training runs then.

        Raises:
            CaptureAlreadyRunningError: If a session is already running.
            ValueError: If neither a PCAP file nor an interface is available.
            FileNotFoundError: If ``pcap`` does not point to an existing file.
            OSError: If the model to load cannot be found or read.
        """
        with self._lock:
            if self._state == "running":
                raise CaptureAlreadyRunningError(
                    "a capture session is already running; stop it first"
                )

            source, label = self._build_source(
                interface=interface, pcap=pcap, bpf=bpf, promiscuous=promiscuous
            )

            model_settings = self._settings.model
            chosen_model_path = (
                model_path if model_path is not None else
                (str(model_settings.path) if model_settings.path is not None else None)
            )
            models: dict[str, AnomalyModel] | None = None
            if chosen_model_path is not None:
                resolved_model_path = model_settings.resolve_model(chosen_model_path)
                models = {
                    "isolation_forest": IsolationForestModel.load(str(resolved_model_path))
                }

            chosen_save_path = (
                model_save_path if model_save_path is not None else
                (str(model_settings.save_path) if model_settings.save_path is not None else None)
            )
            resolved_save_path = (
                model_settings.resolve_model(chosen_save_path)
                if chosen_save_path is not None
                else None
            )

            service = AnalyzerService.from_settings(
                self._settings,
                models=models,
                alert_sinks=[SqliteAlertSink(self._repository)],
                model_save_path=resolved_save_path,
                logger=self._logger,
            )

            self._service = service
            self._source = source
            self._source_label = label
            self._error = None
            self._started_at = datetime.now(timezone.utc)
            self._state = "running"
            self._model_save_path = resolved_save_path
            self._thread = threading.Thread(
                target=self._run, name="sn-analyzer-api-capture", daemon=True
            )
            self._thread.start()

    def stop(self, *, timeout: float = 10.0) -> None:
        """Request the running session to stop and wait briefly for it to finish.

        Safe to call when nothing is running; it then does nothing.
        """
        with self._lock:
            if self._state != "running":
                return
            self._state = "stopping"
            source = self._source
            thread = self._thread

        if source is not None:
            source.stop()
        if thread is not None:
            thread.join(timeout=timeout)

        with self._lock:
            if self._state == "stopping":
                self._state = "idle"

    def status(self) -> CaptureStatus:
        """Return a snapshot of the current session's state and health."""
        with self._lock:
            service = self._service
            return CaptureStatus(
                state=self._state,
                source=self._source_label,
                started_at=self._started_at,
                error=self._error,
                is_ready=service.is_ready if service is not None else False,
                active_flow_count=service.active_flow_count if service is not None else 0,
                evicted_flow_count=(
                    service.evicted_flow_count if service is not None else 0
                ),
                threshold=self._settings.analysis.threshold,
                model_save_path=(
                    str(self._model_save_path) if self._model_save_path is not None else None
                ),
            )

    def close(self) -> None:
        """Stop any running session; called when the API process shuts down."""
        self.stop()

    def _build_source(
        self,
        *,
        interface: str | None,
        pcap: str | None,
        bpf: str | None,
        promiscuous: bool | None,
    ) -> tuple[PacketSource, str]:
        """Resolve request overrides and configuration into one packet source.

        Runs on the calling (request) thread, before the background thread is
        started, so a bad PCAP path fails synchronously with a clear error
        instead of only surfacing later through ``status().error``.
        """
        if pcap is not None:
            resolved = self._settings.capture.resolve_pcap(pcap)
            return PcapFileSource(resolved), f"pcap:{resolved}"

        capture = self._settings.capture
        chosen_interface = interface if interface is not None else capture.interface
        if chosen_interface is None:
            raise ValueError(
                "no packet source: pass 'interface' or 'pcap' in the request, "
                "or set capture.interface in the configuration"
            )
        chosen_bpf = bpf if bpf is not None else capture.bpf_filter
        chosen_promiscuous = (
            promiscuous if promiscuous is not None else capture.promiscuous
        )
        source = LivePacketCapture(
            chosen_interface, bpf_filter=chosen_bpf, promiscuous=chosen_promiscuous
        )
        return source, f"interface:{chosen_interface}"

    def _run(self) -> None:
        """Background-thread target: run the service until the source stops."""
        service, source = self._service, self._source
        assert service is not None and source is not None  # set by start()
        try:
            service.run(source)
        except Exception as exc:
            self._logger.exception("Capture session ended with an error")
            with self._lock:
                self._error = str(exc)
                self._state = "failed"
        else:
            with self._lock:
                if self._state != "failed":
                    self._state = "idle"


@dataclass(slots=True)
class ApiState:
    """Everything a request handler needs, attached to ``app.state`` at startup."""

    settings: AppSettings
    repository: AlertRepository
    controller: CaptureController
