"""Tests for alert sink dispatch and end-to-end alert persistence."""

from __future__ import annotations

from datetime import timedelta
import logging

import pytest

from sn_analyzer.alerting.alert_manager import AlertManager
from sn_analyzer.alerting.sinks import AlertSink
from sn_analyzer.ingestion.base import PacketEnvelope
from sn_analyzer.inference.engine import InferenceResult
from sn_analyzer.storage.alert_repository import AlertRepository, SqliteAlertSink


class _FakeExporter:
    """Evidence exporter that records calls instead of writing PCAP files."""

    def export(self, alert_id: str, packets) -> str:
        return f"/fake/{alert_id}.pcap"


class _RecordingSink(AlertSink):
    def __init__(self) -> None:
        self.alerts: list = []

    def publish(self, alert) -> None:
        self.alerts.append(alert)


class _FailingSink(AlertSink):
    def publish(self, alert) -> None:
        raise RuntimeError("database is locked")


def _packets(ids=(1, 2, 3)) -> list[PacketEnvelope]:
    return [
        PacketEnvelope(packet=object(), captured_at=_now(), source="t", sequence_id=i)
        for i in ids
    ]


def _now():
    from datetime import datetime, timezone

    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_sinks_receive_each_created_alert_once(alert_factory) -> None:
    """A new alert reaches every sink; a suppressed duplicate does not."""
    first, second = _RecordingSink(), _RecordingSink()
    manager = AlertManager(_FakeExporter(), clock=_now, sinks=[first, second])
    result = alert_factory().result

    created = manager.handle(result, _packets())
    duplicate = manager.handle(result, _packets())

    assert created is not None and duplicate is None
    assert first.alerts == [created] and second.alerts == [created]
    assert created.evidence_pcap_path == f"/fake/{created.alert_id}.pcap"


def test_normal_results_are_not_published(alert_factory) -> None:
    """Only anomalous results become alerts."""
    sink = _RecordingSink()
    manager = AlertManager(_FakeExporter(), clock=_now, sinks=[sink])
    anomalous = alert_factory().result
    normal = InferenceResult(
        observation=anomalous.observation,
        anomaly_score=0.1,
        is_anomalous=False,
        model_scores={"isolation_forest": 0.1},
        contributing_features=[],
    )

    assert manager.handle(normal, _packets()) is None
    assert sink.alerts == []


def test_a_failing_sink_neither_loses_the_alert_nor_blocks_other_sinks(
    alert_factory, caplog: pytest.LogCaptureFixture
) -> None:
    """One broken destination must not stop monitoring or starve the others."""
    healthy = _RecordingSink()
    manager = AlertManager(_FakeExporter(), clock=_now, sinks=[_FailingSink(), healthy])

    with caplog.at_level(logging.ERROR):
        alert = manager.handle(alert_factory().result, _packets())

    assert alert is not None
    assert healthy.alerts == [alert]
    assert "_FailingSink" in caplog.text and alert.alert_id in caplog.text


def test_sinks_must_implement_the_interface() -> None:
    """Duck-typed objects are rejected at construction, not at alert time."""
    with pytest.raises(TypeError):
        AlertManager(_FakeExporter(), sinks=[object()])  # type: ignore[list-item]


def test_no_sinks_is_the_default(alert_factory) -> None:
    """Existing callers that pass no sinks keep working."""
    manager = AlertManager(_FakeExporter(), clock=_now)

    assert manager.handle(alert_factory().result, _packets()) is not None


def test_service_persists_alerts_to_sqlite_end_to_end(tmp_path, alert_factory) -> None:
    """Packets in, alert row out: the whole path from ingestion to the database."""
    pytest.importorskip("scapy")
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from sn_analyzer.cli import AnalyzerService

    class _AlwaysAnomalous:
        def evaluate(self, observation):
            return InferenceResult(
                observation=observation,
                anomaly_score=0.97,
                is_anomalous=True,
                model_scores={"isolation_forest": 0.97},
                contributing_features=["packet_count"],
            )

    with AlertRepository(tmp_path / "alerts.db") as repository:
        service = AnalyzerService(
            evidence_directory=tmp_path / "evidence",
            window_packet_count=50,
            alert_cooldown=timedelta(hours=1),
            alert_sinks=[SqliteAlertSink(repository)],
        )
        # Skip baseline training and force a verdict so the test targets the
        # plumbing, not the machine-learning model.
        service._bootstrap_required = False
        service._engine = _AlwaysAnomalous()
        service._alert_manager._exporter = _FakeExporter()

        def send(count: int, first_id: int) -> None:
            for offset in range(count):
                packet = Ether(type=0x0800) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
                    sport=50000, dport=443, flags="S"
                )
                service.process_packet(
                    PacketEnvelope(
                        packet=packet,
                        captured_at=_now() + timedelta(milliseconds=first_id + offset),
                        source="t",
                        sequence_id=first_id + offset,
                    )
                )

        send(50, 0)  # completes one window -> one alert
        send(50, 100)  # same flow inside the cooldown -> suppressed

        stored = repository.list_alerts()

    assert len(stored) == 1
    alert = stored[0]
    assert alert.severity == "critical"
    assert alert.suspicious_ips == ("10.0.0.1", "10.0.0.2")
    assert alert.evidence_pcap_path == f"/fake/{alert.alert_id}.pcap"
    assert alert.result.observation.packet_ids == tuple(range(50))
