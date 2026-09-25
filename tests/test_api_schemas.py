"""Tests for the API's Pydantic response models and their conversion from
internal domain objects. Pure pydantic -- no FastAPI needed."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sn_analyzer.api.schemas import (
    AcknowledgeAlertRequest,
    AlertOut,
    ClearAlertsResponse,
    InterfaceOut,
    ModelFileOut,
    PcapFileOut,
    StartCaptureRequest,
    StatusResponse,
)
from sn_analyzer.api.state import CaptureStatus


def test_alert_out_from_alert_matches_the_domain_object(alert_factory) -> None:
    """Every field the API exposes is drawn correctly from the Alert object."""
    alert = alert_factory(alert_id="a-1", severity="critical", score=0.97)

    out = AlertOut.from_alert(alert)

    key = alert.result.observation.stream_key
    assert out.alert_id == "a-1"
    assert out.severity == "critical"
    assert out.anomaly_score == pytest.approx(0.97)
    assert out.protocol == key.protocol
    assert out.endpoint_a.address == key.endpoint_a.address
    assert out.endpoint_a.port == key.endpoint_a.port
    assert out.endpoint_b.address == key.endpoint_b.address
    assert out.suspicious_ips == alert.suspicious_ips
    assert out.evidence_available is True
    assert out.acknowledged is False
    assert out.feature_values == [
        pytest.approx(v) for v in alert.result.observation.values
    ]
    assert type(out.feature_values[0]) is float  # exact type: np.float64 subclasses float, so isinstance() alone would not catch a missed conversion
    assert out.packet_ids == alert.result.observation.packet_ids


def test_alert_out_reports_missing_evidence(alert_factory) -> None:
    """A None evidence path becomes a plain boolean, not a leaked None/path."""
    alert = alert_factory(evidence_path=None)

    assert AlertOut.from_alert(alert).evidence_available is False


def test_alert_out_reports_acknowledged_state(alert_factory) -> None:
    """A reviewed alert's 'observed' mark is exposed, not silently dropped."""
    alert = alert_factory(acknowledged=True)

    assert AlertOut.from_alert(alert).acknowledged is True


def test_alert_out_serializes_to_plain_json(alert_factory) -> None:
    """The model must actually be JSON-encodable end to end (dates, tuples, floats)."""
    out = AlertOut.from_alert(alert_factory())

    payload = out.model_dump_json()

    assert '"alert_id"' in payload
    # Round-trips through JSON without error is the real assertion here.
    import json

    json.loads(payload)


def test_status_response_from_status_round_trips_every_field() -> None:
    """No field is dropped or renamed between the internal snapshot and the API."""
    status = CaptureStatus(
        state="running",
        source="interface:eth0",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        error=None,
        is_ready=True,
        active_flow_count=12,
        evicted_flow_count=3,
        threshold=0.8,
        model_save_path="models/trained.joblib",
    )

    response = StatusResponse.from_status(status)

    assert response.model_dump() == {
        "state": "running",
        "source": "interface:eth0",
        "started_at": status.started_at,
        "error": None,
        "is_ready": True,
        "active_flow_count": 12,
        "evicted_flow_count": 3,
        "threshold": 0.8,
        "model_save_path": "models/trained.joblib",
    }


def test_status_response_rejects_an_unknown_state() -> None:
    """The Literal type keeps an invalid/typo'd state from silently passing through."""
    with pytest.raises(Exception):
        StatusResponse(
            state="paused",  # type: ignore[arg-type]
            source=None,
            started_at=None,
            error=None,
            is_ready=False,
            active_flow_count=0,
            evicted_flow_count=0,
            threshold=0.8,
        )


def test_interface_out_ip_address_is_optional() -> None:
    """An interface with no assigned address is still representable."""
    interface = InterfaceOut(name="lo", description="Loopback", ip_address=None)

    assert interface.model_dump()["ip_address"] is None


def test_pcap_file_out_round_trips_a_name() -> None:
    assert PcapFileOut(name="traffic.pcap").model_dump() == {"name": "traffic.pcap"}


def test_model_file_out_round_trips_a_name() -> None:
    assert ModelFileOut(name="trained.joblib").model_dump() == {"name": "trained.joblib"}


def test_acknowledge_alert_request_defaults_to_true() -> None:
    """An empty body means 'mark this observed', the common case."""
    assert AcknowledgeAlertRequest().acknowledged is True
    assert AcknowledgeAlertRequest(acknowledged=False).acknowledged is False


def test_clear_alerts_response_round_trips_a_count() -> None:
    assert ClearAlertsResponse(deleted=7).model_dump() == {"deleted": 7}


def test_start_capture_request_defaults_to_all_fields_unset() -> None:
    """An empty request body means 'use the configured defaults for everything'."""
    request = StartCaptureRequest()

    assert request.interface is None
    assert request.pcap is None
    assert request.bpf is None
    assert request.promiscuous is None
    assert request.model_path is None
    assert request.model_save_path is None


def test_start_capture_request_accepts_partial_overrides() -> None:
    """Only the fields the caller sets are populated; others stay None."""
    request = StartCaptureRequest(
        interface="eth0",
        promiscuous=True,
        model_path="trained.joblib",
        model_save_path="new.joblib",
    )

    assert request.interface == "eth0"
    assert request.pcap is None
    assert request.promiscuous is True
    assert request.model_path == "trained.joblib"
    assert request.model_save_path == "new.joblib"
