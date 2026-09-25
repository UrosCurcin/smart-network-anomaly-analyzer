"""End-to-end tests for the FastAPI application.

Skipped automatically wherever fastapi/httpx are not installed (this sandbox
does not have them, so this file could not be executed while writing it --
run `pip install "smart-network-anomaly-analyzer[api]"` and then `pytest` to
exercise it for real). Every test below talks to the app the same way a real
client would: over HTTP, through Starlette's TestClient.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("scapy")
fastapi_testclient = pytest.importorskip("fastapi.testclient")

from sn_analyzer.api import state as state_module
from sn_analyzer.api.app import create_app
from sn_analyzer.config import load_settings
from sn_analyzer.ingestion.base import PacketSource

TestClient = fastapi_testclient.TestClient


class _FakeSource(PacketSource):
    """Blocks until stopped; lets tests control a capture session's lifetime."""

    is_live = False

    def __init__(self, *args, **kwargs) -> None:
        super().__init__()

    def packets(self):
        import threading

        self._mark_running()
        self._released = threading.Event()
        self._released.wait(timeout=10)
        return iter(())

    def stop(self) -> None:
        self._mark_stopping()
        if hasattr(self, "_released"):
            self._released.set()
        self._mark_stopped()


@pytest.fixture
def app(tmp_path):
    settings = load_settings(
        overrides={
            "storage": {
                "database_path": str(tmp_path / "alerts.db"),
                "evidence_dir": str(tmp_path / "evidence"),
            }
        }
    )
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def _insert_alert(client, alert_factory, **kwargs):
    alert = alert_factory(**kwargs)
    client.app.state.sn_state.repository.add_alert(alert)
    return alert


# --- health and docs ------------------------------------------------------------


def test_health_endpoint(client) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root_redirects_to_docs(client) -> None:
    response = client.get("/", follow_redirects=False)

    assert response.status_code in (307, 308)
    assert response.headers["location"] == "/docs"


def test_app_requires_a_configured_database() -> None:
    settings = load_settings(overrides={"storage": {"database_path": None}})

    with pytest.raises(ValueError, match="requires alert storage"):
        create_app(settings)


# --- status and capture control --------------------------------------------------


def test_status_starts_idle(client) -> None:
    response = client.get("/status")

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "idle"
    assert body["active_flow_count"] == 0


def test_capture_start_stop_cycle(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)

    started = client.post("/capture/start", json={"pcap": "traffic.pcap"})
    assert started.status_code == 202
    assert started.json()["state"] == "running"
    # A bare filename resolves under the default capture.pcap_dir ("logs").
    assert started.json()["source"] == f"pcap:{Path('logs') / 'traffic.pcap'}"

    status = client.get("/status").json()
    assert status["state"] == "running"

    stopped = client.post("/capture/stop")
    assert stopped.status_code == 200
    assert stopped.json()["state"] == "idle"


def test_capture_start_twice_is_a_conflict(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)
    client.post("/capture/start", json={"pcap": "a.pcap"})

    second = client.post("/capture/start", json={"pcap": "b.pcap"})

    assert second.status_code == 409
    client.post("/capture/stop")


def test_capture_start_without_a_source_is_a_bad_request(client) -> None:
    response = client.post("/capture/start", json={})

    assert response.status_code == 400
    assert "no packet source" in response.json()["detail"]


def test_capture_start_with_missing_pcap_is_a_bad_request(client) -> None:
    response = client.post("/capture/start", json={"pcap": "/no/such/file.pcap"})

    assert response.status_code == 400


def test_stop_when_idle_is_not_an_error(client) -> None:
    response = client.post("/capture/stop")

    assert response.status_code == 200
    assert response.json()["state"] == "idle"


def test_list_interfaces_maps_capture_error_to_503(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sn_analyzer.ingestion.live_capture import LiveCaptureError

    def broken(**kwargs):
        raise LiveCaptureError("Npcap is not installed")

    monkeypatch.setattr(
        "sn_analyzer.api.routers.capture.list_capture_interfaces", broken
    )

    response = client.get("/capture/interfaces")

    assert response.status_code == 503


def test_list_interfaces_returns_the_enumerated_list(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sn_analyzer.ingestion.live_capture import CaptureInterface

    fixed = [CaptureInterface(name="eth0", description="Ethernet", ip_address="10.0.0.5")]
    monkeypatch.setattr(
        "sn_analyzer.api.routers.capture.list_capture_interfaces", lambda: fixed
    )

    response = client.get("/capture/interfaces")

    assert response.status_code == 200
    assert response.json() == [
        {"name": "eth0", "description": "Ethernet", "ip_address": "10.0.0.5"}
    ]


def test_list_pcaps_returns_empty_when_the_directory_does_not_exist(tmp_path) -> None:
    """A pcap_dir that hasn't been created yet is not an error, just empty."""
    settings = load_settings(
        overrides={
            "storage": {
                "database_path": str(tmp_path / "alerts.db"),
                "evidence_dir": str(tmp_path / "evidence"),
            },
            "capture": {"pcap_dir": str(tmp_path / "no-such-pcap-dir")},
        }
    )
    with TestClient(create_app(settings)) as scoped_client:
        response = scoped_client.get("/capture/pcaps")

    assert response.status_code == 200
    assert response.json() == []


def test_list_pcaps_lists_only_capture_files_sorted_by_name(tmp_path) -> None:
    """Only *.pcap/*.pcapng in pcap_dir are listed, alphabetically, ignoring other files."""
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir()
    (pcap_dir / "b.pcap").write_bytes(b"")
    (pcap_dir / "a.pcapng").write_bytes(b"")
    (pcap_dir / "notes.txt").write_bytes(b"")

    settings = load_settings(
        overrides={
            "storage": {
                "database_path": str(tmp_path / "alerts.db"),
                "evidence_dir": str(tmp_path / "evidence"),
            },
            "capture": {"pcap_dir": str(pcap_dir)},
        }
    )
    with TestClient(create_app(settings)) as scoped_client:
        response = scoped_client.get("/capture/pcaps")

    assert response.status_code == 200
    assert response.json() == [{"name": "a.pcapng"}, {"name": "b.pcap"}]


def test_list_models_returns_empty_when_the_directory_does_not_exist(tmp_path) -> None:
    """A model_dir that hasn't been created yet is not an error, just empty."""
    settings = load_settings(
        overrides={
            "storage": {
                "database_path": str(tmp_path / "alerts.db"),
                "evidence_dir": str(tmp_path / "evidence"),
            },
            "model": {"model_dir": str(tmp_path / "no-such-model-dir")},
        }
    )
    with TestClient(create_app(settings)) as scoped_client:
        response = scoped_client.get("/capture/models")

    assert response.status_code == 200
    assert response.json() == []


def test_list_models_lists_only_joblib_files_sorted_by_name(tmp_path) -> None:
    """Only *.joblib in model_dir is listed, alphabetically, ignoring other files."""
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    (model_dir / "b.joblib").write_bytes(b"")
    (model_dir / "a.joblib").write_bytes(b"")
    (model_dir / "readme.txt").write_bytes(b"")

    settings = load_settings(
        overrides={
            "storage": {
                "database_path": str(tmp_path / "alerts.db"),
                "evidence_dir": str(tmp_path / "evidence"),
            },
            "model": {"model_dir": str(model_dir)},
        }
    )
    with TestClient(create_app(settings)) as scoped_client:
        response = scoped_client.get("/capture/models")

    assert response.status_code == 200
    assert response.json() == [{"name": "a.joblib"}, {"name": "b.joblib"}]


def test_capture_start_accepts_a_model_save_path_override(
    client, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """model_save_path in the request overrides model.save_path for this session."""
    monkeypatch.setattr(state_module, "PcapFileSource", _FakeSource)

    started = client.post(
        "/capture/start", json={"pcap": "traffic.pcap", "model_save_path": "new.joblib"}
    )

    assert started.status_code == 202
    settings = client.app.state.sn_state.settings
    expected = str(settings.model.model_dir / "new.joblib")
    assert started.json()["model_save_path"] == expected

    client.post("/capture/stop")


# --- alert history ----------------------------------------------------------------


def test_list_alerts_empty(client) -> None:
    response = client.get("/alerts")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


def test_alert_stats_reports_all_severities_including_zero(client) -> None:
    response = client.get("/alerts/stats")

    assert response.status_code == 200
    assert response.json() == {"low": 0, "medium": 0, "high": 0, "critical": 0}


def test_list_and_get_a_stored_alert(client, alert_factory) -> None:
    _insert_alert(client, alert_factory, alert_id="a-1", severity="high")

    listed = client.get("/alerts")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["alert_id"] == "a-1"

    fetched = client.get("/alerts/a-1")
    assert fetched.status_code == 200
    assert fetched.json()["severity"] == "high"


def test_get_unknown_alert_is_404(client) -> None:
    response = client.get("/alerts/does-not-exist")

    assert response.status_code == 404


def test_list_alerts_filters_by_severity(client, alert_factory) -> None:
    _insert_alert(client, alert_factory, alert_id="low-1", severity="low")
    _insert_alert(client, alert_factory, alert_id="high-1", severity="high")

    response = client.get("/alerts", params={"severity": "high"})

    assert response.status_code == 200
    ids = [item["alert_id"] for item in response.json()["items"]]
    assert ids == ["high-1"]


def test_list_alerts_rejects_an_unknown_severity(client) -> None:
    response = client.get("/alerts", params={"severity": "urgent"})

    assert response.status_code == 422  # FastAPI's own query validation


def test_list_alerts_rejects_a_naive_timestamp(client, alert_factory) -> None:
    _insert_alert(client, alert_factory, alert_id="a-1")

    response = client.get("/alerts", params={"since": "2026-01-01T00:00:00"})

    assert response.status_code == 400


def test_evidence_download_returns_the_file(client, alert_factory, tmp_path) -> None:
    evidence_dir = client.app.state.sn_state.settings.storage.evidence_dir
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = evidence_dir / "a-1.pcap"
    evidence_file.write_bytes(b"fake-pcap-bytes")
    _insert_alert(client, alert_factory, alert_id="a-1", evidence_path=str(evidence_file))

    response = client.get("/alerts/a-1/evidence")

    assert response.status_code == 200
    assert response.content == b"fake-pcap-bytes"
    assert response.headers["content-type"] == "application/vnd.tcpdump.pcap"


def test_evidence_download_404_when_none_was_retained(client, alert_factory) -> None:
    _insert_alert(client, alert_factory, alert_id="a-1", evidence_path=None)

    response = client.get("/alerts/a-1/evidence")

    assert response.status_code == 404


def test_evidence_path_outside_evidence_dir_is_refused(client, alert_factory) -> None:
    """A stored path escaping the configured directory is never served."""
    _insert_alert(
        client, alert_factory, alert_id="a-1", evidence_path="/etc/definitely-not-evidence.pcap"
    )

    response = client.get("/alerts/a-1/evidence")

    assert response.status_code == 500


def test_list_alerts_filters_by_acknowledged(client, alert_factory) -> None:
    _insert_alert(client, alert_factory, alert_id="seen", acknowledged=True)
    _insert_alert(client, alert_factory, alert_id="unseen", acknowledged=False)

    seen = client.get("/alerts", params={"acknowledged": "true"})
    unseen = client.get("/alerts", params={"acknowledged": "false"})

    assert [item["alert_id"] for item in seen.json()["items"]] == ["seen"]
    assert [item["alert_id"] for item in unseen.json()["items"]] == ["unseen"]


def test_acknowledge_alert_marks_it_observed(client, alert_factory) -> None:
    _insert_alert(client, alert_factory, alert_id="a-1")

    response = client.post("/alerts/a-1/acknowledge")

    assert response.status_code == 200
    assert response.json()["acknowledged"] is True
    assert client.get("/alerts/a-1").json()["acknowledged"] is True


def test_acknowledge_alert_can_clear_the_mark(client, alert_factory) -> None:
    _insert_alert(client, alert_factory, alert_id="a-1", acknowledged=True)

    response = client.post("/alerts/a-1/acknowledge", json={"acknowledged": False})

    assert response.status_code == 200
    assert response.json()["acknowledged"] is False


def test_acknowledge_unknown_alert_is_404(client) -> None:
    response = client.post("/alerts/does-not-exist/acknowledge")

    assert response.status_code == 404


def test_delete_alert_removes_it_and_its_evidence_file(client, alert_factory) -> None:
    evidence_dir = client.app.state.sn_state.settings.storage.evidence_dir
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = evidence_dir / "a-1.pcap"
    evidence_file.write_bytes(b"fake-pcap-bytes")
    _insert_alert(client, alert_factory, alert_id="a-1", evidence_path=str(evidence_file))

    response = client.delete("/alerts/a-1")

    assert response.status_code == 204
    assert client.get("/alerts/a-1").status_code == 404
    assert not evidence_file.exists()


def test_delete_alert_without_evidence_just_removes_the_row(client, alert_factory) -> None:
    _insert_alert(client, alert_factory, alert_id="a-1", evidence_path=None)

    response = client.delete("/alerts/a-1")

    assert response.status_code == 204
    assert client.get("/alerts/a-1").status_code == 404


def test_delete_unknown_alert_is_404(client) -> None:
    response = client.delete("/alerts/does-not-exist")

    assert response.status_code == 404


def test_delete_alert_tolerates_an_already_missing_evidence_file(
    client, alert_factory, tmp_path
) -> None:
    """The row is still the important part; a vanished file must not block the delete."""
    missing_file = tmp_path / "evidence" / "already-gone.pcap"
    _insert_alert(client, alert_factory, alert_id="a-1", evidence_path=str(missing_file))

    response = client.delete("/alerts/a-1")

    assert response.status_code == 204
    assert client.get("/alerts/a-1").status_code == 404


def test_clear_alerts_empties_history_and_removes_evidence_files(
    client, alert_factory
) -> None:
    evidence_dir = client.app.state.sn_state.settings.storage.evidence_dir
    evidence_dir.mkdir(parents=True, exist_ok=True)
    kept_files = []
    for i in range(3):
        evidence_file = evidence_dir / f"a-{i}.pcap"
        evidence_file.write_bytes(b"fake-pcap-bytes")
        kept_files.append(evidence_file)
        _insert_alert(client, alert_factory, alert_id=f"a-{i}", evidence_path=str(evidence_file))
    _insert_alert(client, alert_factory, alert_id="no-evidence", evidence_path=None)

    response = client.delete("/alerts")

    assert response.status_code == 200
    assert response.json() == {"deleted": 4}
    assert client.get("/alerts").json()["total"] == 0
    for evidence_file in kept_files:
        assert not evidence_file.exists()


def test_clear_alerts_on_an_empty_history_reports_zero(client) -> None:
    response = client.delete("/alerts")

    assert response.status_code == 200
    assert response.json() == {"deleted": 0}
