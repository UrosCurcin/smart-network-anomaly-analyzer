"""Shared fixtures for Smart Network Anomaly Analyzer tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sn_analyzer.ingestion.base import PacketEnvelope


@pytest.fixture
def base_time() -> datetime:
    """Return a stable, timezone-aware timestamp for deterministic tests."""
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def envelope_factory(base_time: datetime):
    """Build packet envelopes with deterministic source, sequence, and times."""

    def factory(packet: object, sequence_id: int, offset_seconds: float = 0.0) -> PacketEnvelope:
        return PacketEnvelope(
            packet=packet,
            captured_at=base_time + timedelta(seconds=offset_seconds),
            source="pytest",
            sequence_id=sequence_id,
        )

    return factory


@pytest.fixture
def alert_factory(base_time: datetime):
    """Build valid, anomalous alerts without needing Scapy or a model."""
    from uuid import uuid4

    import numpy as np

    from sn_analyzer.alerting.alert_manager import Alert
    from sn_analyzer.features.schemas import FeatureVector
    from sn_analyzer.inference.engine import InferenceResult
    from sn_analyzer.ingestion.stream_demux import Endpoint, StreamKey

    def factory(
        *,
        alert_id: str | None = None,
        severity: str = "high",
        score: float = 0.9,
        offset_seconds: float = 0.0,
        stream_key: StreamKey | None = None,
        evidence_path: str | None = "/evidence/example.pcap",
        packet_ids: tuple[int, ...] = (1, 2, 3),
        acknowledged: bool = False,
    ) -> Alert:
        key = stream_key or StreamKey(
            "TCP", Endpoint("10.0.0.1", 50000), Endpoint("10.0.0.2", 443)
        )
        moment = base_time + timedelta(seconds=offset_seconds)
        observation = FeatureVector(
            stream_key=key,
            timestamp=moment,
            values=np.array([10.0, 2.5, 0.125]),
            feature_names=("packet_count", "tcp_syn_ratio", "packet_length_mean"),
            packet_ids=packet_ids,
        )
        result = InferenceResult(
            observation=observation,
            anomaly_score=score,
            is_anomalous=True,
            model_scores={"isolation_forest": score},
            contributing_features=["packet_count", "tcp_syn_ratio"],
        )
        return Alert(
            alert_id=alert_id or str(uuid4()),
            created_at=moment,
            severity=severity,
            result=result,
            suspicious_ips=(key.endpoint_a.address, key.endpoint_b.address),
            evidence_pcap_path=evidence_path,
            acknowledged=acknowledged,
        )

    return factory
