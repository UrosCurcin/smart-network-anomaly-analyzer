"""Tests for live-mode housekeeping: the idle tick and the active-flow cap."""

from __future__ import annotations

from datetime import timedelta
import threading

import pytest

pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from sn_analyzer.cli import AnalyzerService
from sn_analyzer.ingestion.base import PacketSource
from sn_analyzer.ingestion.live_capture import LivePacketCapture
from sn_analyzer.ingestion.pcap_reader import PcapFileSource


def _packet(source_port: int):
    """Build a TCP packet; each source port is a distinct flow."""
    return Ether(type=0x0800) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=source_port, dport=443, flags="A"
    )


def _record_flushes(service: AnalyzerService, on_flush=None) -> list:
    """Wrap ``_flush_window`` so tests can see which flows were flushed."""
    flushed: list = []
    original = service._flush_window

    def recording(stream_key) -> None:
        flushed.append(stream_key)
        if on_flush is not None:
            on_flush()
        original(stream_key)

    service._flush_window = recording  # type: ignore[method-assign]
    return flushed


def test_tick_flushes_window_open_for_the_window_duration(
    tmp_path, base_time, envelope_factory
) -> None:
    """A quiet flow's partial window is scored once it is old enough."""
    service = AnalyzerService(
        evidence_directory=tmp_path / "evidence",
        window_duration=timedelta(seconds=30),
        window_packet_count=50,
    )
    flushed = _record_flushes(service)
    service.process_packet(envelope_factory(_packet(1001), 1))

    assert service.tick(base_time + timedelta(seconds=29)) == 0
    assert flushed == []
    assert service.tick(base_time + timedelta(seconds=30)) == 1
    assert len(flushed) == 1
    assert service._windows == {}


def test_tick_expires_idle_streams(tmp_path, base_time, envelope_factory) -> None:
    """Idle expiry runs from the tick even though no new packet arrived."""
    service = AnalyzerService(
        evidence_directory=tmp_path / "evidence",
        window_duration=timedelta(hours=1),
        stream_idle_timeout=timedelta(seconds=5),
    )
    service.process_packet(envelope_factory(_packet(1001), 1))

    assert service.tick(base_time + timedelta(seconds=4)) == 0
    assert service.active_flow_count == 1
    assert service.tick(base_time + timedelta(seconds=5)) == 1
    assert service.active_flow_count == 0


def test_tick_requires_timezone_aware_time(tmp_path) -> None:
    """A naive timestamp is rejected instead of being misread as UTC."""
    from datetime import datetime

    service = AnalyzerService(evidence_directory=tmp_path / "evidence")

    with pytest.raises(ValueError):
        service.tick(datetime(2026, 1, 1))


def test_flow_cap_scores_and_drops_the_least_recently_active_flow(
    tmp_path, envelope_factory
) -> None:
    """Exceeding the cap flushes the oldest flow, so memory stays bounded."""
    service = AnalyzerService(
        evidence_directory=tmp_path / "evidence", max_active_flows=2
    )
    flushed = _record_flushes(service)
    first = envelope_factory(_packet(1001), 1)
    second = envelope_factory(_packet(1002), 2, 1)
    third = envelope_factory(_packet(1003), 3, 2)

    for envelope in (first, second, third):
        service.process_packet(envelope)

    assert service.active_flow_count == 2
    assert len(service._windows) == 2
    assert service.evicted_flow_count == 1
    assert flushed == [service._demultiplexer.key_for(first)]


def test_flow_cap_must_be_positive(tmp_path) -> None:
    """Invalid caps and tick intervals are rejected at construction."""
    with pytest.raises(ValueError):
        AnalyzerService(evidence_directory=tmp_path, max_active_flows=0)
    with pytest.raises(ValueError):
        AnalyzerService(evidence_directory=tmp_path, tick_interval=timedelta(0))


def test_only_interface_capture_is_marked_live(tmp_path) -> None:
    """Offline replay must never receive wall-clock housekeeping."""
    pcap = tmp_path / "empty.pcap"
    pcap.write_bytes(b"")

    assert LivePacketCapture("eth0").is_live is True
    assert PcapFileSource(pcap).is_live is False


class _QuietLiveSource(PacketSource):
    """Live-style source that yields one packet and then stays silent."""

    is_live = True

    def __init__(self, envelope) -> None:
        super().__init__()
        self._envelope = envelope
        self._release = threading.Event()

    def packets(self):
        self._mark_running()
        yield self._envelope
        self._release.wait(timeout=10)

    def stop(self) -> None:
        self._mark_stopping()
        self._release.set()
        self._mark_stopped()


def test_run_ticker_flushes_a_quiet_flow_while_the_source_is_silent(
    tmp_path, base_time, envelope_factory
) -> None:
    """Without new packets, the background ticker still flushes the window."""
    flushed_while_quiet = threading.Event()
    service = AnalyzerService(
        evidence_directory=tmp_path / "evidence",
        window_duration=timedelta(seconds=30),
        tick_interval=timedelta(milliseconds=20),
        # The injected clock is ten minutes after the packet, so the window is due.
        clock=lambda: base_time + timedelta(minutes=10),
    )
    _record_flushes(service, on_flush=flushed_while_quiet.set)
    source = _QuietLiveSource(envelope_factory(_packet(1001), 1))
    runner = threading.Thread(target=service.run, args=(source,), daemon=True)

    runner.start()
    try:
        # ``stop()`` has not been called yet, so this flush came from the ticker.
        assert flushed_while_quiet.wait(timeout=5.0)
    finally:
        source.stop()
        runner.join(timeout=5.0)

    assert not runner.is_alive()
