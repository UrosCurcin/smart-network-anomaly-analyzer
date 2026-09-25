"""Unit tests for numerical packet-window feature extraction."""

from __future__ import annotations

from datetime import timedelta

import numpy as np
import pytest

scapy = pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from sn_analyzer.features.packet_features import FeatureExtractor
from sn_analyzer.ingestion.stream_demux import Endpoint, StreamKey


def test_tcp_window_features_have_correct_counts_flags_and_timing(
    base_time, envelope_factory
) -> None:
    """TCP flag ratios and basic statistics match a known synthetic sequence."""
    packets = [
        Ether(type=0x0800) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=50000, dport=443, flags=flag
        )
        for flag in ("S", "A", "F", "R")
    ]
    offsets = (0.0, 1.0, 3.0, 6.0)
    envelopes = [
        envelope_factory(packet, sequence_id, offset)
        for sequence_id, (packet, offset) in enumerate(zip(packets, offsets), start=1)
    ]
    stream_key = StreamKey("TCP", Endpoint("10.0.0.1", 50000), Endpoint("10.0.0.2", 443))

    vector = FeatureExtractor().extract_window_features(
        stream_key, envelopes, base_time + timedelta(seconds=6)
    )
    features = vector.feature_map

    assert vector.values.dtype.kind == "f"
    assert not vector.values.flags.writeable
    assert vector.packet_ids == (1, 2, 3, 4)
    assert features["packet_count"] == 4.0
    assert features["byte_count"] == pytest.approx(sum(len(packet) for packet in packets))
    assert features["tcp_packet_ratio"] == 1.0
    assert features["tcp_syn_ratio"] == pytest.approx(0.25)
    assert features["tcp_ack_ratio"] == pytest.approx(0.25)
    assert features["tcp_fin_ratio"] == pytest.approx(0.25)
    assert features["tcp_rst_ratio"] == pytest.approx(0.25)
    assert features["inter_arrival_mean_seconds"] == pytest.approx(2.0)
    assert features["inter_arrival_variance_seconds"] == pytest.approx(2.0 / 3.0)


def test_udp_window_has_zero_tcp_flag_ratios(base_time, envelope_factory) -> None:
    """Missing TCP layers produce zero TCP-specific values rather than errors."""
    packets = [
        Ether(type=0x0800) / IP(src="10.0.0.3", dst="10.0.0.4") / UDP(
            sport=40000, dport=53
        ),
        Ether(type=0x0800) / IP(src="10.0.0.4", dst="10.0.0.3") / UDP(
            sport=53, dport=40000
        ),
    ]
    envelopes = [
        envelope_factory(packet, index, float(index))
        for index, packet in enumerate(packets, start=1)
    ]
    stream_key = StreamKey("UDP", Endpoint("10.0.0.3", 40000), Endpoint("10.0.0.4", 53))

    vector = FeatureExtractor().extract_window_features(
        stream_key, envelopes, base_time + timedelta(seconds=2)
    )
    features = vector.feature_map

    assert features["udp_packet_ratio"] == 1.0
    assert features["tcp_packet_ratio"] == 0.0
    assert features["tcp_syn_ratio"] == 0.0
    assert features["tcp_ack_ratio"] == 0.0
    assert features["tcp_fin_ratio"] == 0.0
    assert features["tcp_rst_ratio"] == 0.0
