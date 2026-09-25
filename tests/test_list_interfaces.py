"""Tests for cross-platform capture-interface enumeration and its CLI command."""

from __future__ import annotations

import pytest

from sn_analyzer import cli
from sn_analyzer.ingestion.live_capture import (
    CaptureInterface,
    LiveCaptureError,
    list_capture_interfaces,
)


class _FakeIface:
    """Stand-in for the raw objects Scapy's ``conf.ifaces`` yields."""

    def __init__(self, name=None, description=None, ip=None) -> None:
        self.name = name
        self.description = description
        self.ip = ip


def test_interfaces_are_converted_and_sorted_by_name() -> None:
    """Raw Scapy interface objects become plain, sorted CaptureInterface values."""
    raw = [
        _FakeIface(name="eth1", description="Ethernet 1", ip="10.0.0.5"),
        _FakeIface(name="eth0", description="Ethernet 0", ip=None),
    ]

    interfaces = list_capture_interfaces(ifaces_provider=lambda: raw)

    assert interfaces == [
        CaptureInterface(name="eth0", description="Ethernet 0", ip_address=None),
        CaptureInterface(name="eth1", description="Ethernet 1", ip_address="10.0.0.5"),
    ]


def test_interfaces_without_a_usable_name_are_skipped() -> None:
    """A malformed or loopback-only entry with no name must not break the list."""
    raw = [_FakeIface(name=""), _FakeIface(name=None), _FakeIface(name="lo", ip="127.0.0.1")]

    interfaces = list_capture_interfaces(ifaces_provider=lambda: raw)

    assert [interface.name for interface in interfaces] == ["lo"]


def test_no_interfaces_is_an_empty_list_not_an_error() -> None:
    """An empty capture environment is valid; it just has nothing to show."""
    assert list_capture_interfaces(ifaces_provider=lambda: []) == []


def test_provider_failure_is_wrapped_in_live_capture_error() -> None:
    """A Scapy/Npcap failure while enumerating interfaces is reported clearly."""

    def broken():
        raise OSError("Npcap is not installed")

    with pytest.raises(LiveCaptureError, match="enumerate"):
        list_capture_interfaces(ifaces_provider=broken)


def test_missing_scapy_is_reported_clearly(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without Scapy installed, the error names the missing dependency."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "scapy.config":
            raise ImportError("no module named scapy.config")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(LiveCaptureError, match="Scapy is required"):
        list_capture_interfaces()


# --- CLI integration -----------------------------------------------------------


def test_list_interfaces_prints_each_interface_and_returns_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """The command needs no packet source and prints a readable table."""
    fixed = [
        CaptureInterface(name="eth0", description="Ethernet", ip_address="10.0.0.5"),
        CaptureInterface(name="wlan0", description="Wi-Fi", ip_address=None),
    ]
    monkeypatch.setattr(cli, "list_capture_interfaces", lambda: fixed)

    code = cli.main(["--list-interfaces"])

    assert code == 0
    out = capsys.readouterr().out
    assert "eth0" in out and "10.0.0.5" in out
    assert "wlan0" in out and "Wi-Fi" in out


def test_list_interfaces_with_no_interfaces_still_returns_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """No interfaces found is reported, not treated as failure."""
    monkeypatch.setattr(cli, "list_capture_interfaces", lambda: [])

    code = cli.main(["--list-interfaces"])

    assert code == 0
    assert "No capture interfaces" in capsys.readouterr().out


def test_list_interfaces_failure_returns_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """A Scapy/Npcap failure is reported on stderr with a non-zero exit code."""

    def broken():
        raise LiveCaptureError("Npcap is not installed")

    monkeypatch.setattr(cli, "list_capture_interfaces", broken)

    code = cli.main(["--list-interfaces"])

    assert code == 1
    assert "Npcap is not installed" in capsys.readouterr().err


def test_list_interfaces_does_not_require_a_packet_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--list-interfaces alone is a complete, valid invocation."""
    monkeypatch.setattr(cli, "list_capture_interfaces", lambda: [])

    assert cli.main(["--list-interfaces"]) == 0
