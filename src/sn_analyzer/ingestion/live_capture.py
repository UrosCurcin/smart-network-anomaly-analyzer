"""Live, bounded-memory packet capture backed by Scapy's ``AsyncSniffer``."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from queue import Empty, Full, Queue
from threading import Event
from typing import Any

from .base import PacketEnvelope, PacketSource


class LiveCaptureError(RuntimeError):
    """Raised when live packet capture cannot be started or operated safely."""


@dataclass(frozen=True, slots=True)
class CaptureInterface:
    """One network interface Scapy can capture from.

    Attributes:
        name: Value to pass as ``--interface``.  On Linux/macOS this is a
            device name such as ``eth0``; on Windows, Scapy exposes a
            human-readable name such as ``Ethernet`` or ``Wi-Fi`` here rather
            than the underlying ``\\Device\\NPF_{GUID}`` path.
        description: Longer, human-readable label, when Scapy provides one.
        ip_address: The interface's first IPv4/IPv6 address, if any.
    """

    name: str
    description: str
    ip_address: str | None


def list_capture_interfaces(
    *, ifaces_provider: Callable[[], Iterable[Any]] | None = None
) -> list[CaptureInterface]:
    """Return capture-candidate interfaces, sorted by name.

    This only enumerates interfaces; it does not check whether the current
    user is authorized to capture on them.

    Args:
        ifaces_provider: Testing hook that replaces Scapy's own
            ``conf.ifaces`` as the source of raw interface objects.

    Raises:
        LiveCaptureError: If Scapy is unavailable or interfaces cannot be
            enumerated (for example, missing Npcap on Windows).
    """
    if ifaces_provider is None:
        try:
            from scapy.config import conf
        except ImportError as exc:
            raise LiveCaptureError(
                "Scapy is required to list capture interfaces; install the "
                "project's packet-capture dependency."
            ) from exc
        ifaces_provider = lambda: conf.ifaces.values()  # noqa: E731

    try:
        raw_interfaces = list(ifaces_provider())
    except LiveCaptureError:
        raise
    except Exception as exc:
        raise LiveCaptureError(
            "unable to enumerate network interfaces; on Windows this usually "
            "means Npcap is not installed"
        ) from exc

    interfaces = [
        interface
        for raw in raw_interfaces
        if (interface := _to_capture_interface(raw)) is not None
    ]
    return sorted(interfaces, key=lambda interface: interface.name)


def _to_capture_interface(raw: Any) -> CaptureInterface | None:
    """Convert one Scapy interface object, skipping ones with no usable name."""
    name = getattr(raw, "name", None)
    if not name or not str(name).strip():
        return None
    description = getattr(raw, "description", None) or ""
    ip_address = getattr(raw, "ip", None)
    return CaptureInterface(
        name=str(name),
        description=str(description),
        ip_address=str(ip_address) if ip_address else None,
    )



class LivePacketCapture(PacketSource):
    """Stream authorized interface traffic as :class:`PacketEnvelope` objects.

    Scapy captures packets in a background thread.  Its callback puts packets
    into a bounded queue, allowing a slower feature-extraction pipeline to
    apply back-pressure by dropping new packets rather than exhausting memory.
    A source instance is single-use and must not be consumed concurrently.
    """

    is_live = True

    def __init__(self,
                 interface: str,
                 bpf_filter: str | None = None,
                 promiscuous: bool = False,
                 queue_size: int = 10000,
                 poll_interval_seconds: float = 0.25,
                 clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Configure, but do not start, an interface capture.

        Args:
            interface: Authorized network interface name known to Scapy/Npcap.
            bpf_filter: Optional Berkeley Packet Filter expression.
            promiscuous: Whether the capture adapter should request promiscuous
                mode.  This should only be enabled with explicit authorization.
            queue_size: Maximum packets retained while consumers are busy.
            poll_interval_seconds: Maximum wait before a stop request is seen.
            clock: Injectable UTC-capable clock used only when a packet lacks a
                capture timestamp.
        """
        super().__init__()
        if not interface or not interface.strip():
            raise ValueError("interface must be non-empty string")
        if bpf_filter is not None and not bpf_filter.strip():
            raise ValueError("bpf_filter must be non-empty when provided")
        if queue_size <= 0:
            raise ValueError("queue_size must be greater than zero")
        if poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be greater than zero")

        self._interface = interface.strip()
        self._bpf_filter = bpf_filter.strip() if bpf_filter is not None else None
        self._promiscuous = promiscuous
        self._queue: Queue[PacketEnvelope] = Queue(maxsize=queue_size)
        self._poll_interval_seconds = poll_interval_seconds
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._stop_event = Event()
        self._sniffer: Any | None = None
        self._iterations_started = False
        self._next_sequence_id = 0
        self._dropped_packets = 0

    @property
    def interface(self) -> str:
        """Return the configured network interface name."""
        return self._interface

    @property
    def promiscuous(self) -> bool:
        """Return whether promiscuous mode was requested for this capture."""
        return self._promiscuous

    @property
    def bpf_filter(self) -> str | None:
        """Return the configured BPF filter expression, if any."""
        return self._bpf_filter

    @property
    def dropped_packets(self) -> int:
        """Return packets discarded because the bounded queue was full."""
        with self._lock:
            return self._dropped_packets


    def packets(self) -> Iterator[PacketEnvelope]:
        """Yield packets until ``stop()`` is called or capture initialization fails.

        Raises:
        RuntimeError: If this single-use source is consumed more than once.
        LiveCaptureError: If Scapy is unavailable or cannot start capture.
        """

        with self._lock:
            if self._iterations_started:
                raise RuntimeError("a LivePacketCapture can be only consumed once")
            self._iterations_started = True

        if self.stop_requested:
            self._mark_stopped()
            return

        self._mark_running()
        try:
            if not self._start_sniffer():
                return

            while not self.stop_requested:
                try:
                    envelope = self._queue.get(timeout=self._poll_interval_seconds)
                except Empty:
                    continue

                if self.stop_requested:
                    break
                yield envelope
        except LiveCaptureError:
            self._mark_failed()
            raise
        except Exception as exc:
            self._mark_failed()
            raise LiveCaptureError(
                f"life capture failed on interface: {self._interface!r}"
            )from exc
        finally:
            self.stop()


    def stop(self) -> None:
        """Request a graceful, idempotent shutdown of the Scapy capture thread."""
        self._stop_event.set()
        self._mark_stopping()

        with self._lock:
            sniffer = self._sniffer
            self._sniffer = None

        if sniffer is not None:
            try:
                # ``join=True`` avoids leaving a capture thread behind.
                sniffer.stop(join=True)
            except Exception:
                #It may already be stopped; shutdown must remain imdopotent.
                pass
        self._mark_stopped()

    def _start_sniffer(self) -> bool:
        """Instantiate and start Scapy's background sniffer exactly once."""

        try:
            from scapy.sendrecv import AsyncSniffer
        except ImportError as exc:
            raise LiveCaptureError(
                "Scapy is required for live capture; install the project's "
                "packet-capture dependency."
            ) from exc

        with self._lock:
            if self._stop_event.is_set():
                return False
            if self._sniffer is not None:
                raise LiveCaptureError("live capture has already been started")

            options: dict[str, Any] = {
                "iface": self._interface,
                "prn": self._on_packet,
                "store": False,
                "promisc": self._promiscuous,
            }

            if self._bpf_filter is not None:
                options["filter"] = self._bpf_filter

            try:
                sniffer = AsyncSniffer(**options)
                sniffer.start()
            except Exception as exc:
                raise LiveCaptureError(
                    f"unable to start capture on interface: {self._interface!r}"
                )
            self._sniffer = sniffer
        return True

    def _on_packet(self, packet: Any) -> None:
        """Convert a Scapy callback packet to an envelope without blocking."""
        if self._stop_event.is_set():
            return

        try:
            captured_at = self._packet_timestamp(packet)
            with self._lock:
                sequence_id = self._next_sequence_id
                self._next_sequence_id += 1
            envelope = PacketEnvelope(
                packet = packet,
                captured_at = captured_at,
                source = self._interface,
                sequence_id = sequence_id,
                metadata={"interface": self._interface},
            )
            self._queue.put_nowait(envelope)
        except Full:
            with self._lock:
                self._dropped_packets += 1
        except Exception:
            # Callback exceptions must not terminate Scapy's capture thread.
            # Invalid packets are intentionally skipped; future observability
            # can publish this count through the metrics component.
            with self._lock:
                self._dropped_packets += 1

    def _packet_timestamp(self, packet: Any) -> datetime:
        """Use Scapy's packet timestamp, falling back to the injected clock."""
        try:
            captured_at = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
        except (AttributeError, ValueError, OSError, OverflowError, TypeError):
            captured_at = self._clock()

        if captured_at.tzinfo is None or captured_at.utcoffset() is None:
            raise LiveCaptureError("clock must return a timezone-aware datetime")

        return captured_at.astimezone(timezone.utc)


