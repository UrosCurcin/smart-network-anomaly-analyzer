"""Offline PCAP and PCAPNG ingestion backed by Scapy.

Scapy is imported only when a reader starts, keeping package imports usable in
environments that install ingestion dependencies separately.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import PacketEnvelope, PacketSource


class PcapReadError(RuntimeError):
    """Raised when a PCAP cannot be opened or decoded safely."""


class PcapFileSource(PacketSource):
    """Yield packets from one PCAP/PCAPNG file without loading it all in memory.

    A source instance is single-use.  This avoids accidental duplicate replay
    and guarantees sequence IDs uniquely identify packets within that source.
    """

    def __init__(self, path: str | Path) -> None:
        """Validate and register an existing PCAP or PCAPNG file.

        Args:
            path: Path to a packet capture readable by Scapy.

        Raises:
            FileNotFoundError: If ``path`` does not exist.
            IsADirectoryError: If ``path`` refers to a directory.
        """
        super().__init__()
        capture_path = Path(path).expanduser().resolve(strict=True)
        if not capture_path.is_file():
            raise IsADirectoryError(f"PCAP path is not a file: {capture_path}")

        self._path = capture_path
        self._reader: Any | None = None
        self._iteration_started = False

    @property
    def path(self) -> Path:
        """Return the resolved, immutable path of the capture file."""
        return self._path

    def packets(self) -> Iterator[PacketEnvelope]:
        """Stream envelopes in on-disk order from the configured capture file.

        The method is intentionally single-use because an iterator may have
        already advanced the underlying file and the base interface promises
        source-local monotonic sequence IDs.

        Raises:
            RuntimeError: If called more than once on the same source.
            PcapReadError: If Scapy is unavailable or the file is unreadable.
        """
        with self._lock:
            if self._iteration_started:
                raise RuntimeError("a PcapFileSource can only be consumed once")
            self._iteration_started = True

        if self.stop_requested:
            self._mark_stopped()
            return

        self._mark_running()
        sequence_id = 0

        try:
            reader = self._open_reader()
            with self._lock:
                self._reader = reader

            while not self.stop_requested:
                try:
                    packet = next(reader)
                except StopIteration:
                    break
                except Exception as exc:
                    if self.stop_requested:
                        break
                    raise PcapReadError(
                        f"failed reading packet {sequence_id} from {self._path}"
                    ) from exc

                if self.stop_requested:
                    break

                packet = self._decode_raw_network_packet(packet)

                yield PacketEnvelope(
                    packet=packet,
                    captured_at=self._packet_timestamp(packet, sequence_id),
                    source=str(self._path),
                    sequence_id=sequence_id,
                    metadata={
                        "capture_path": str(self._path),
                        "capture_index": sequence_id,
                    },
                )
                sequence_id += 1
        except PcapReadError:
            self._mark_failed()
            raise
        except Exception as exc:
            self._mark_failed()
            raise PcapReadError(f"unable to open PCAP file: {self._path}") from exc
        finally:
            self._close_reader()
            self._mark_stopped()

    def stop(self) -> None:
        """Request shutdown and close Scapy's reader to unblock file access."""
        self._mark_stopping()
        self._close_reader()
        self._mark_stopped()

    def _open_reader(self) -> Any:
        """Create Scapy's streaming reader with a helpful missing-dependency error."""
        try:
            from scapy.utils import PcapReader
        except ImportError as exc:
            raise PcapReadError(
                "Scapy is required for PCAP ingestion; install the project's "
                "packet-capture dependency."
            ) from exc

        try:
            return PcapReader(str(self._path))
        except Exception as exc:
            raise PcapReadError(f"unable to open PCAP file: {self._path}") from exc

    def _packet_timestamp(self, packet: Any, sequence_id: int) -> datetime:
        """Convert Scapy's capture timestamp to a timezone-aware UTC datetime."""
        try:
            return datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
        except (AttributeError, OSError, OverflowError, TypeError, ValueError) as exc:
            raise PcapReadError(
                f"packet {sequence_id} in {self._path} has an invalid timestamp"
            ) from exc

    @staticmethod
    def _decode_raw_network_packet(packet: Any) -> Any:
        """Recover IP/ARP layers when a capture was exposed as raw bytes.

        Most Ethernet PCAPs are decoded by Scapy automatically.  Some capture
        tools, however, record an ambiguous or unsupported link type and yield
        a ``Raw`` packet despite containing Ethernet, IPv4, IPv6, or ARP bytes.
        Re-decoding at ingestion keeps downstream stream grouping and feature
        extraction independent of that capture-format quirk.  Packets that are
        not recognizable IP/ARP traffic are returned unchanged.
        """
        try:
            from scapy.layers.inet import IP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import ARP, Ether
        except ImportError:
            # ``_open_reader`` already provides the actionable dependency error.
            return packet

        try:
            if packet.haslayer(IP) or packet.haslayer(IPv6) or packet.haslayer(ARP):
                return packet

            raw_bytes = bytes(packet)
            decoded_candidates: list[Any] = []
            # Try Ethernet first: a destination MAC can coincidentally start
            # with an IPv4/IPv6 version nibble, but Ether() verifies the inner
            # EtherType before exposing an IP or ARP layer.
            if len(raw_bytes) >= 14:
                decoded_candidates.append(Ether(raw_bytes))
            if raw_bytes and raw_bytes[0] >> 4 == 4:
                decoded_candidates.append(IP(raw_bytes))
            elif raw_bytes and raw_bytes[0] >> 4 == 6:
                decoded_candidates.append(IPv6(raw_bytes))

            for decoded in decoded_candidates:
                if decoded.haslayer(IP) or decoded.haslayer(IPv6) or decoded.haslayer(ARP):
                    if hasattr(packet, "time"):
                        decoded.time = packet.time
                    return decoded
        except Exception:
            # The caller will retain unsupported packets for diagnostics rather
            # than discarding a capture solely because best-effort decoding failed.
            return packet
        return packet

    def _close_reader(self) -> None:
        """Close the active Scapy reader once; safe to call repeatedly."""
        with self._lock:
            reader = self._reader
            self._reader = None

        if reader is not None:
            try:
                reader.close()
            except Exception:
                # Closing is best-effort; a prior read/open error is more useful.
                pass
