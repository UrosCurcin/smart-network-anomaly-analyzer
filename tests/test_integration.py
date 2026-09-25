"""End-to-end PCAP replay test for the analyzer service."""

from __future__ import annotations

from pathlib import Path

import pytest

scapy = pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from sn_analyzer.cli import AnalyzerService
from sn_analyzer.ingestion.pcap_reader import PcapFileSource


class _RecordingAlertManager:
    """Test double that records alerts without writing evidence artifacts."""

    def __init__(self) -> None:
        self.alerts = []

    def handle(self, result, packets):
        """Record an alert only if the engine marks it anomalous."""
        if result.is_anomalous:
            self.alerts.append((result, list(packets)))
        return None


def test_benign_pcap_replay_trains_baseline_without_false_alerts(tmp_path: Path) -> None:
    """A fixed benign PCAP completes warm-up and does not produce an alert."""
    pcap_path = tmp_path / "benign.pcap"
    packets = [
        Ether(type=0x0800)
        / IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(sport=50000, dport=443, flags="A")
        for _ in range(200)
    ]
    wrpcap(str(pcap_path), packets)

    service = AnalyzerService(
        evidence_directory=tmp_path / "evidence",
        window_packet_count=50,
        bootstrap_windows=3,
        threshold=0.80,
    )
    recording_alerts = _RecordingAlertManager()
    service._alert_manager = recording_alerts

    service.run(PcapFileSource(pcap_path))

    assert service.is_ready
    assert recording_alerts.alerts == []
