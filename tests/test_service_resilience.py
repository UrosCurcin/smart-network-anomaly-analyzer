"""Tests that one bad packet cannot terminate an analyzer session."""

from __future__ import annotations

import pytest

pytest.importorskip("scapy")

from sn_analyzer.cli import AnalyzerService


class _ExplodingPacket:
    """Raises a non-demultiplexer exception when Scapy layers are inspected."""

    def haslayer(self, layer: object) -> bool:
        raise RuntimeError("simulated decoder failure")


def test_process_packet_skips_packet_that_fails_layer_inspection(
    tmp_path, envelope_factory
) -> None:
    """A packet whose layers cannot be read is skipped, not propagated."""
    service = AnalyzerService(evidence_directory=tmp_path / "evidence")

    service.process_packet(envelope_factory(_ExplodingPacket(), 1))

    assert service._windows == {}


def test_process_packet_safety_net_logs_unforeseen_demultiplexer_bug(
    tmp_path, envelope_factory, caplog
) -> None:
    """Even a non-StreamDemultiplexingError is logged with a traceback and skipped."""

    def broken_add(envelope: object) -> None:
        raise RuntimeError("unforeseen demultiplexer bug")

    service = AnalyzerService(evidence_directory=tmp_path / "evidence")
    service._demultiplexer.add = broken_add  # type: ignore[method-assign]

    with caplog.at_level("WARNING"):
        service.process_packet(envelope_factory(object(), 7))

    assert service._windows == {}
    assert "sequence_id=7" in caplog.text
    assert "unforeseen demultiplexer bug" in caplog.text
