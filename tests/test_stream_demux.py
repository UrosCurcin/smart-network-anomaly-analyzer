"""Unit tests for canonical stream identities and idle expiration."""

from __future__ import annotations

from datetime import timedelta

import pytest

scapy = pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from sn_analyzer.ingestion.stream_demux import (
    Endpoint,
    StreamDemultiplexer,
    StreamDemultiplexingError,
    StreamKey,
)


def test_endpoint_and_stream_key_are_canonicalized() -> None:
    """Equivalent reversed endpoint pairs produce an identical stream key."""
    first = StreamKey("tcp", Endpoint("10.0.0.2", 443), Endpoint("10.0.0.1", 50000))
    reversed_key = StreamKey(
        "TCP", Endpoint("10.0.0.1", 50000), Endpoint("10.0.0.2", 443)
    )

    assert first == reversed_key
    assert first.protocol == "TCP"
    assert first.endpoint_a == Endpoint("10.0.0.1", 50000)
    assert Endpoint("2001:0db8::1", 53).address == "2001:db8::1"


def test_tcp_and_udp_packets_use_bidirectional_streams(envelope_factory) -> None:
    """TCP and UDP reply traffic must map to the stream created by its request."""
    demultiplexer = StreamDemultiplexer()

    tcp_request = Ether(type=0x0800) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=50000, dport=443, flags="S"
    )
    tcp_reply = Ether(type=0x0800) / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
        sport=443, dport=50000, flags="SA"
    )
    udp_request = Ether(type=0x0800) / IP(src="10.0.0.3", dst="10.0.0.4") / UDP(
        sport=53000, dport=53
    )
    udp_reply = Ether(type=0x0800) / IP(src="10.0.0.4", dst="10.0.0.3") / UDP(
        sport=53, dport=53000
    )

    tcp_key = demultiplexer.add(envelope_factory(tcp_request, 1))
    assert demultiplexer.add(envelope_factory(tcp_reply, 2, 1)) == tcp_key

    udp_key = demultiplexer.add(envelope_factory(udp_request, 3, 2))
    assert demultiplexer.add(envelope_factory(udp_reply, 4, 3)) == udp_key
    assert tcp_key.protocol == "TCP"
    assert udp_key.protocol == "UDP"
    assert demultiplexer.snapshot(tcp_key).packet_count == 2


def test_arp_packets_use_a_bidirectional_stream(envelope_factory) -> None:
    """ARP request/reply endpoint pairs are retained in one canonical stream."""
    demultiplexer = StreamDemultiplexer()
    request = Ether(type=0x0806) / ARP(
        op=1, psrc="192.168.1.10", pdst="192.168.1.20"
    )
    reply = Ether(type=0x0806) / ARP(
        op=2, psrc="192.168.1.20", pdst="192.168.1.10"
    )

    key = demultiplexer.add(envelope_factory(request, 10))
    assert demultiplexer.add(envelope_factory(reply, 11, 1)) == key
    assert key.protocol == "ARP"
    assert key.endpoint_a.port is None


def test_idle_streams_expire_at_configured_timeout(base_time, envelope_factory) -> None:
    """A flow remains active before, and expires at, the idle timeout boundary."""
    demultiplexer = StreamDemultiplexer(idle_timeout=timedelta(seconds=5))
    packet = Ether(type=0x0800) / IP(src="10.1.0.1", dst="10.1.0.2") / TCP(
        sport=1, dport=2
    )
    key = demultiplexer.add(envelope_factory(packet, 1))

    assert demultiplexer.expire_idle_streams(base_time + timedelta(seconds=4)) == []
    assert demultiplexer.expire_idle_streams(base_time + timedelta(seconds=5)) == [key]
    assert demultiplexer.active_stream_count == 0


def test_ipv6_tcp_packets_use_bidirectional_streams(envelope_factory) -> None:
    """IPv6 TCP request/reply traffic maps to one canonical stream.

    Regression test: the IPv6 branch used to index ``packet[IPv6][IP]``, which
    raises ``IndexError`` because an IPv6 packet has no IPv4 layer.
    """
    demultiplexer = StreamDemultiplexer()
    request = Ether(type=0x86DD) / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(
        sport=50000, dport=443, flags="S"
    )
    reply = Ether(type=0x86DD) / IPv6(src="2001:db8::2", dst="2001:db8::1") / TCP(
        sport=443, dport=50000, flags="SA"
    )

    key = demultiplexer.add(envelope_factory(request, 1))

    assert demultiplexer.add(envelope_factory(reply, 2, 1)) == key
    assert key.protocol == "TCP"
    assert key.endpoint_a == Endpoint("2001:db8::1", 50000)
    assert key.endpoint_b == Endpoint("2001:db8::2", 443)
    assert demultiplexer.snapshot(key).packet_count == 2


def test_ipv6_udp_and_ip_only_packets_are_supported(envelope_factory) -> None:
    """IPv6 UDP keeps its ports; IPv6 without a transport layer has none."""
    demultiplexer = StreamDemultiplexer()
    udp = Ether(type=0x86DD) / IPv6(src="fe80::1", dst="fe80::2") / UDP(
        sport=5353, dport=5353
    )
    ip_only = Ether(type=0x86DD) / IPv6(src="fe80::1", dst="fe80::2")

    udp_key = demultiplexer.add(envelope_factory(udp, 1))
    ip_only_key = demultiplexer.add(envelope_factory(ip_only, 2, 1))

    assert udp_key.protocol == "UDP"
    assert udp_key.endpoint_a.port == 5353
    assert ip_only_key.protocol == "IPV6"
    assert ip_only_key.endpoint_a.port is None
    assert ip_only_key != udp_key


class _MalformedPacket:
    """Claims to have IP layers but fails when they are accessed."""

    def haslayer(self, layer: object) -> bool:
        return True

    def __getitem__(self, layer: object) -> object:
        raise IndexError("Layer not found")


def test_malformed_packet_raises_only_stream_demultiplexing_error(
    envelope_factory,
) -> None:
    """Unexpected Scapy failures are normalized to the documented error type."""
    demultiplexer = StreamDemultiplexer()

    with pytest.raises(StreamDemultiplexingError):
        demultiplexer.add(envelope_factory(_MalformedPacket(), 1))

    assert demultiplexer.active_stream_count == 0


def test_unsupported_packet_still_raises_stream_demultiplexing_error(
    envelope_factory,
) -> None:
    """A frame with no IPv4, IPv6, or ARP layer is rejected, not tracked."""
    demultiplexer = StreamDemultiplexer()

    with pytest.raises(StreamDemultiplexingError):
        demultiplexer.add(envelope_factory(Ether(type=0x88CC), 1))


def _tcp_envelope(envelope_factory, source_port: int, sequence_id: int, offset: float = 0.0):
    """Build an envelope for a distinct TCP flow identified by its source port."""
    packet = Ether(type=0x0800) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=source_port, dport=443, flags="S"
    )
    return envelope_factory(packet, sequence_id, offset)


def test_max_streams_evicts_least_recently_active_stream(envelope_factory) -> None:
    """At the cap, a new flow evicts the flow that was active longest ago."""
    demultiplexer = StreamDemultiplexer(max_streams=2)

    first = demultiplexer.add(_tcp_envelope(envelope_factory, 1001, 1))
    second = demultiplexer.add(_tcp_envelope(envelope_factory, 1002, 2, 1))
    # Touching the first flow makes the second one the least recently active.
    demultiplexer.add(_tcp_envelope(envelope_factory, 1001, 3, 2))
    third = demultiplexer.add(_tcp_envelope(envelope_factory, 1003, 4, 3))

    assert demultiplexer.active_stream_count == 2
    assert demultiplexer.snapshot(first) is not None
    assert demultiplexer.snapshot(third) is not None
    assert demultiplexer.snapshot(second) is None
    assert demultiplexer.drain_evicted() == [second]
    assert demultiplexer.drain_evicted() == []
    assert demultiplexer.evicted_total == 1


def test_streams_are_unbounded_without_a_cap(envelope_factory) -> None:
    """Leaving ``max_streams`` unset keeps the previous, unlimited behavior."""
    demultiplexer = StreamDemultiplexer()

    for index in range(50):
        demultiplexer.add(_tcp_envelope(envelope_factory, 2000 + index, index))

    assert demultiplexer.active_stream_count == 50
    assert demultiplexer.drain_evicted() == []


def test_max_streams_must_be_positive() -> None:
    """A zero or negative cap is a configuration error."""
    with pytest.raises(ValueError):
        StreamDemultiplexer(max_streams=0)

