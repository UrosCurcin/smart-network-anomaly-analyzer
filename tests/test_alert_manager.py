"""Unit tests for alert severity, evidence artifacts, and cooldown behavior."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

scapy = pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

from sn_analyzer.alerting.alert_manager import AlertManager, EvidencePcapExporter
from sn_analyzer.features.schemas import FeatureVector
from sn_analyzer.inference.engine import InferenceResult
from sn_analyzer.ingestion.stream_demux import Endpoint, StreamKey


def _anomalous_result(base_time: datetime, score: float = 0.96) -> InferenceResult:
    """Create a deterministic anomalous result for alerting tests."""
    key = StreamKey("TCP", Endpoint("10.0.0.1", 50000), Endpoint("10.0.0.2", 443))
    observation = FeatureVector(
        stream_key=key,
        timestamp=base_time,
        values=np.array([10.0, 2.0]),
        feature_names=("packet_count", "tcp_syn_ratio"),
        packet_ids=(1,),
    )
    return InferenceResult(
        observation=observation,
        anomaly_score=score,
        is_anomalous=True,
        model_scores={"isolation_forest": score},
        contributing_features=["packet_count"],
    )


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0.69, "low"), (0.70, "medium"), (0.85, "high"), (0.95, "critical")],
)
def test_severity_tiers(score: float, expected: str) -> None:
    """Normalized scores map to the documented operational severity tiers."""
    assert AlertManager._severity_for(score) == expected


def test_alert_exports_atomic_evidence_and_suppresses_duplicates(
    tmp_path: Path, base_time: datetime, envelope_factory
) -> None:
    """One alert creates readable evidence; a duplicate in cooldown is ignored."""
    packet = Ether(type=0x0800) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=50000, dport=443, flags="S"
    )
    envelope = envelope_factory(packet, 1)
    exporter = EvidencePcapExporter(tmp_path / "evidence")
    manager = AlertManager(exporter, clock=lambda: base_time)

    alert = manager.handle(_anomalous_result(base_time), [envelope])
    duplicate = manager.handle(_anomalous_result(base_time), [envelope])

    assert alert is not None
    assert alert.severity == "critical"
    assert alert.evidence_pcap_path is not None
    evidence_path = Path(alert.evidence_pcap_path)
    assert evidence_path.is_file()
    assert len(rdpcap(str(evidence_path))) == 1
    assert not list((tmp_path / "evidence").glob("*.partial.pcap"))
    assert duplicate is None
