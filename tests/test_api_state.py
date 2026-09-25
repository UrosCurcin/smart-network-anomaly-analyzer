"""Tests for the framework-free capture controller behind the HTTP API.

None of this needs FastAPI: CaptureController is plain Python by design, so
its start/stop/status behavior is verified directly here.
"""

from __future__ import annotations

from pathlib import Path
import threading

import pytest

pytest.importorskip("scapy")

from sn_analyzer.api import state as state_module
from sn_analyzer.api.state import (
    ApiState,
    CaptureAlreadyRunningError,
    CaptureController,
)
from sn_analyzer.config import load_settings
from sn_analyzer.ingestion.base import PacketSource
from sn_analyzer.storage.alert_repository import AlertRepository


class _FakeSource(PacketSource):
    """Controllable stand-in for a real packet source: blocks until stopped."""

    is_live = False

    def __init__(self, *args, **kwargs) -> None:
        super().__init__()
        self.init_args = args
        self.init_kwargs = kwargs
        self._released = threading.Event()

    def packets(self):
        self._mark_running()
        self._released.wait(timeout=10)
        return iter(())

    def stop(self) -> None:
        self._mark_stopping()
        self._released.set()
        self._mark_stopped()


class _BrokenSource(PacketSource):
    """A source whose ``packets()`` raises, to exercise the failed state."""

    is_live = False

    def packets(self):
        self._mark_running()
        raise RuntimeError("capture device vanished")

    def stop(self) -> None:
        self._mark_stopping()
        self._mark_stopped()


@pytest.fixture
def repository():
    with AlertRepository(":memory:") as repo:
        yield repo


@pytest.fixture
def controller(repository):
    settings = load_settings()
    return CaptureController(settings, repository)


def _wait_until(predicate, *, timeout: float = 5.0) -> None:
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition was not met in time")


def test_status_when_idle() -> None:
    """A freshly constructed controller reports a clean idle snapshot."""
    settings = load_settings()
    with AlertRepository(":memory:") as repository:
        controller = CaptureController(settings, repository)
        status = controller.status()

    assert status.state == "idle"
    assert status.source is None
    assert status.started_at is None
    assert status.error is None
    assert status.is_ready is False
    assert status.active_flow_count == 0
    assert status.threshold == settings.analysis.threshold
    assert status.model_save_path is None


def test_start_requires_a_packet_source(controller: CaptureController) -> None:
    """No pcap, no interface override, and no configured interface is an error."""
    with pytest.raises(ValueError, match="no packet source"):
        controller.start()


def test_missing_pcap_file_fails_synchronously(controller: CaptureController) -> None:
    """A bad path is reported immediately, not only through the status endpoint."""
    with pytest.raises(FileNotFoundError):
        controller.start(pcap="/no/such/file.pcap")

    assert controller.status().state == "idle"


def test_start_with_pcap_runs_and_stop_returns_to_idle(
    monkeypatch: pytest.MonkeyPatch, controller: CaptureController
) -> None:
    """A full start -> running -> stop -> idle cycle, using a fake source."""
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)

    controller.start(pcap="traffic.pcap")
    status = controller.status()
    assert status.state == "running"
    # A bare filename is resolved under capture.pcap_dir ("logs" by default).
    assert status.source == f"pcap:{Path('logs') / 'traffic.pcap'}"
    assert status.started_at is not None

    controller.stop()

    assert controller.status().state == "idle"


def test_start_with_pcap_full_path_is_used_unchanged(
    monkeypatch: pytest.MonkeyPatch, controller: CaptureController
) -> None:
    """A path that already names a directory is never redirected into pcap_dir."""
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)
    given = str(Path("elsewhere") / "traffic.pcap")

    controller.start(pcap=given)

    assert controller.status().source == f"pcap:{given}"
    controller.stop()


def test_start_twice_is_rejected(
    monkeypatch: pytest.MonkeyPatch, controller: CaptureController
) -> None:
    """A second start while one is already running does not replace it."""
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)
    controller.start(pcap="a.pcap")

    with pytest.raises(CaptureAlreadyRunningError):
        controller.start(pcap="b.pcap")

    assert controller.status().source == f"pcap:{Path('logs') / 'a.pcap'}"
    controller.stop()


def test_stop_when_idle_is_a_no_op(controller: CaptureController) -> None:
    """Stopping with nothing running must not raise or change the state."""
    controller.stop()

    assert controller.status().state == "idle"


def test_interface_overrides_and_config_fallback(
    monkeypatch: pytest.MonkeyPatch, repository
) -> None:
    """A request field overrides the setting; an omitted field falls back to it."""
    settings = load_settings(
        overrides={
            "capture": {"interface": "eth0", "bpf_filter": "tcp", "promiscuous": False}
        }
    )
    controller = CaptureController(settings, repository)
    monkeypatch.setattr(state_module, "LivePacketCapture", _FakeSource)

    # No overrides: falls back entirely to configuration.
    controller.start()
    assert controller.status().source == "interface:eth0"
    controller.stop()

    # Every field overridden.
    controller.start(interface="wlan0", bpf="udp", promiscuous=True)
    status = controller.status()
    assert status.source == "interface:wlan0"
    controller.stop()


def test_failed_session_is_reported_in_status(
    monkeypatch: pytest.MonkeyPatch, controller: CaptureController
) -> None:
    """A source that raises while running surfaces as state='failed' with a message."""
    monkeypatch.setattr(state_module, "PcapFileSource", lambda path: _BrokenSource())

    controller.start(pcap="broken.pcap")
    _wait_until(lambda: controller.status().state == "failed")

    status = controller.status()
    assert status.state == "failed"
    assert "capture device vanished" in status.error


def test_close_stops_a_running_session(
    monkeypatch: pytest.MonkeyPatch, controller: CaptureController
) -> None:
    """close() is the shutdown hook the API's lifespan calls; it must not hang."""
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)
    controller.start(pcap="a.pcap")

    controller.close()

    assert controller.status().state == "idle"


def test_model_path_override_loads_a_pretrained_model_and_skips_training(
    monkeypatch: pytest.MonkeyPatch, repository, tmp_path: Path
) -> None:
    """A request-supplied model_path overrides model.path, resolved under model.model_dir."""
    pytest.importorskip("sklearn")
    import numpy as np

    from sn_analyzer.models.isolation_forest import IsolationForestModel

    model_dir = tmp_path / "models"
    model_dir.mkdir()
    trained = IsolationForestModel(n_estimators=5, random_state=1)
    trained.fit(np.random.default_rng(0).normal(size=(20, 3)))
    trained.save(str(model_dir / "trained.joblib"))

    settings = load_settings(overrides={"model": {"model_dir": str(model_dir)}})
    controller = CaptureController(settings, repository)
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)

    controller.start(pcap="a.pcap", model_path="trained.joblib")

    # A pre-trained model is ready immediately; no baseline warm-up needed.
    assert controller.status().is_ready is True
    controller.stop()


def test_model_save_path_override_is_resolved_and_reported_in_status(
    monkeypatch: pytest.MonkeyPatch, repository, tmp_path: Path
) -> None:
    """A request-supplied model_save_path overrides model.save_path for this session."""
    settings = load_settings(overrides={"model": {"model_dir": str(tmp_path / "models")}})
    controller = CaptureController(settings, repository)
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)

    controller.start(pcap="a.pcap", model_save_path="new.joblib")

    expected = str(tmp_path / "models" / "new.joblib")
    assert controller.status().model_save_path == expected
    controller.stop()


def test_model_save_path_falls_back_to_configured_save_path(
    monkeypatch: pytest.MonkeyPatch, repository, tmp_path: Path
) -> None:
    """With no override, the configured model.save_path is used and reported."""
    settings = load_settings(
        overrides={
            "model": {"save_path": "trained.joblib", "model_dir": str(tmp_path / "models")}
        }
    )
    controller = CaptureController(settings, repository)
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)

    controller.start(pcap="a.pcap")

    expected = str(tmp_path / "models" / "trained.joblib")
    assert controller.status().model_save_path == expected
    controller.stop()


def test_api_state_bundles_settings_repository_and_controller(repository) -> None:
    """ApiState is a plain, inspectable bundle attached to app.state."""
    settings = load_settings()
    controller = CaptureController(settings, repository)

    bundle = ApiState(settings=settings, repository=repository, controller=controller)

    assert bundle.settings is settings
    assert bundle.repository is repository
    assert bundle.controller is controller
