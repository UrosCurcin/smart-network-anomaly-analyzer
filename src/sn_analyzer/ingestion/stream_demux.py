"""Bidirectional network-flow demultiplexing for Scapy packet envelopes."""


from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from threading import RLock
from typing import Any

from .base import PacketEnvelope


class StreamDemultiplexingError(ValueError):
    """Raised when a packet cannot be mapped to a supported network stream."""


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A network endpoint consisting of an IP address and optional port."""

    address: str
    port: int | None = None

    def __post_init__(self) -> None:
        """Canonicalize the address and validate an optional transport port."""
        try:
            normalized_address = ip_address(self.address).compressed
        except ValueError as exc:
            raise StreamDemultiplexingError(
                f"Invalid IP address: {exc}"
            )from exc

        if self.port is not None and not 0 <= self.port <= 65535:
            raise StreamDemultiplexingError("Port must be between 0 and 65535")

        object.__setattr__(self, "address", normalized_address)

    @property
    def _sort_key(self) -> tuple[int, int, int]:
        """Return a stable ordering token used to normalize flow direction."""
        address = ip_address(self.address)
        # "None" sorts before port zero, which is a valid transport port.
        port_value = -1 if self.port is None else self.port
        return(address.version, int(address), port_value)


@dataclass(frozen=True, slots=True)
class StreamKey:
    """Canonical bidirectional identity for packets belonging to one flow."""

    protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint

    def __post_init__(self) -> None:
        """Uppercase protocol names and order endpoints deterministically."""
        protocol = self.protocol.upper()
        if not protocol:
            raise StreamDemultiplexingError("protocol must be non-empty string")

        endpoint_A = self.endpoint_a
        endpoint_B = self.endpoint_b

        if endpoint_B._sort_key < endpoint_A._sort_key:
            endpoint_A, endpoint_B = endpoint_B, endpoint_A

        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "endpoint_a", endpoint_A)
        object.__setattr__(self, "endpoint_b", endpoint_B)

@dataclass(frozen=True, slots=True)
class StreamSnapshot:
    """Read-only activity summary for a currently tracked stream."""

    key: StreamKey
    first_seen: datetime
    last_seen: datetime
    packet_count: int

@dataclass(slots=True)
class _StreamState:
    """Mutable internal state retained only by : class:`StreamDemultiplexer`."""

    first_seen: datetime
    last_seen: datetime
    packet_count: int


class StreamDemultiplexer:
    """Assign packets to bidirectional IP/port streams and track their activity.

    Stream keys retain both endpoints in canonical order.  A TCP packet from
    ``10.0.0.1:50000`` to ``10.0.0.2:443`` and its reply therefore receive the
    same key.  IP-only protocols use ``None`` as their port.
    """

    def __init__(
        self,
        idle_timeout: timedelta = timedelta(minutes=5),
        max_streams: int | None = None,
    ) -> None:
        """Create a demultiplexer with an idle timeout and optional flow cap.

        Args:
            idle_timeout: Inactivity after which a stream is expired.
            max_streams: Maximum streams tracked at once, or ``None`` for no
                limit.  When a new stream arrives at the limit, the least
                recently active stream is evicted to make room and is reported
                through :meth:`drain_evicted`.  This bounds memory when traffic
                (a port scan, for example) creates flows faster than they idle out.
        """
        if idle_timeout <= timedelta(0):
            raise ValueError("idle_timeout must be greater than zero")
        if max_streams is not None and max_streams <= 0:
            raise ValueError("max_streams must be greater than zero when provided")
        self._idle_timeout = idle_timeout
        self._max_streams = max_streams
        # Ordered from least to most recently active so eviction is O(1).
        self._streams: OrderedDict[StreamKey, _StreamState] = OrderedDict()
        self._evicted: list[StreamKey] = []
        self._evicted_total = 0
        self._lock = RLock()

    @property
    def idle_timeout(self) -> timedelta:
        """Return the interval after which an inactive stream is expired."""
        return self._idle_timeout

    @property
    def max_streams(self) -> int | None:
        """Return the concurrent-stream limit, or ``None`` when unlimited."""
        return self._max_streams

    @property
    def evicted_total(self) -> int:
        """Return how many streams have been evicted because of the cap."""
        with self._lock:
            return self._evicted_total

    def drain_evicted(self) -> list[StreamKey]:
        """Return and clear the streams evicted since the previous call.

        Callers that keep per-stream data (such as packet windows) must process
        these keys, otherwise that data would outlive the tracked stream.
        """
        with self._lock:
            evicted, self._evicted = self._evicted, []
        return evicted

    @property
    def active_stream_count(self) -> int:
        """Return the number of streams currently retained in memory."""
        with self._lock:
            return len(self._streams)

    def key_for(self, envelope: PacketEnvelope) -> StreamKey:
        """Return the canonical flow key for a supported Scapy packet.

        Supported protocol families are IPv4, IPv6, and ARP.  TCP and UDP
        ports are included when present; ICMP, ARP, and IP-only traffic use
        IP endpoints without ports.

        Raises:
            StreamDemultiplexingError: If packet layers are unsupported or
        required IP address or port fields are malformed.
        """
        return self._key_from_packet(envelope.packet)

    def add(self, envelope: PacketEnvelope) -> StreamKey:
        """Track one packet and return its canonical stream key.

        Capture timestamps may be out of order in an offline PCAP.  The
        stream's first and last timestamps are therefore maintained as the
        minimum and maximum observed values rather than arrival order.
        """
        key = self.key_for(envelope)
        observed_at = envelope.captured_at_utc

        with self._lock:
            state = self._streams.get(key)
            if state is None:
                if (
                    self._max_streams is not None
                    and len(self._streams) >= self._max_streams
                ):
                    evicted_key, _ = self._streams.popitem(last=False)
                    self._evicted.append(evicted_key)
                    self._evicted_total += 1
                self._streams[key] = _StreamState(
                    first_seen=observed_at,
                    last_seen=observed_at,
                    packet_count=1,
                )
            else:
                state.first_seen = min(state.first_seen, observed_at)
                state.last_seen = max(state.last_seen, observed_at)
                state.packet_count += 1
                self._streams.move_to_end(key)
        return key

    def snapshot(self, key: StreamKey) -> StreamSnapshot | None:
        """Return a read-only stream summary, or ``None`` when it is unknown."""
        with self._lock:
            state = self._streams.get(key)
            if state is None:
                return None
            return StreamSnapshot(
                key=key,
                first_seen=state.first_seen,
                last_seen=state.last_seen,
                packet_count=state.packet_count,
            )

    def expire_idle_streams(self, now: datetime) -> list[StreamKey]:
        """Remove and return streams inactive for at least ``idle_timeout``.

        Args:
            now: Time against which the most recent capture timestamp is
                compared.  It must include timezone information.
        """

        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must include timezone information")
        now_utc = now.astimezone(timezone.utc)

        with self._lock:
            expired = [
                key
                for key, state in self._streams.items()
                if now_utc - state.last_seen >= self._idle_timeout
            ]
            for key in expired:
                del self._streams[key]
        return expired


    def _key_from_packet(self, packet: Any) -> StreamKey:
        """Extract endpoint and protocol information from Scapy packet layers."""
        try:
            from scapy.layers.inet import ICMP,IP,TCP,UDP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import ARP
        except ImportError as exc:
            raise StreamDemultiplexingError(
                "Scapy is requiered to demultiplex packet streams."
            ) from exc

        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                protocol, source_port, destination_port = self._transport_details(
                    packet, TCP, UDP, ICMP, "ICMP"
                )
                # ``ip_layer`` is already the IPv4 layer, so read its fields
                # directly instead of indexing it a second time.
                return StreamKey(
                    protocol=protocol,
                    endpoint_a=Endpoint(str(ip_layer.src), source_port),
                    endpoint_b=Endpoint(str(ip_layer.dst), destination_port),
                )

            if packet.haslayer(IPv6):
                ip_layer = packet[IPv6]
                protocol, source_port, destination_port = self._transport_details(
                    packet, TCP, UDP, None, "IPv6"
                )
                return StreamKey(
                    protocol=protocol,
                    endpoint_a=Endpoint(str(ip_layer.src), source_port),
                    endpoint_b=Endpoint(str(ip_layer.dst), destination_port),
                )

            if packet.haslayer(ARP):
                arp_layer = packet[ARP]
                return StreamKey(
                    protocol="ARP",
                    endpoint_a=Endpoint(str(arp_layer.psrc)),
                    endpoint_b=Endpoint(str(arp_layer.pdst)),
                )
        except StreamDemultiplexingError:
            # Already the expected, well-described rejection (bad IP or port).
            raise
        except Exception as exc:
            # Malformed or truncated packets can make Scapy raise IndexError,
            # AttributeError, struct errors and so on.  Normalize them to the
            # one error type callers handle, so a single bad packet cannot
            # abort a monitoring session.
            raise StreamDemultiplexingError(
                f"unable to read stream identity from packet: {exc!r}"
            ) from exc

        raise StreamDemultiplexingError(
            "packet does not contain a supported IPv4, IPv6, or ARP layer"
        )

    @staticmethod
    def _transport_details(
            packet: Any,
            tcp_layer: Any,
            udp_layer: Any,
            icmp_layer: Any | None,
            fallback_protocol: str,
    )-> tuple[str, int|None, int|None]:
        """Return protocol name and ports, retaining IP-only packets as flows."""
        if packet.haslayer(tcp_layer):
            layer = packet[tcp_layer]
            return(
                "TCP",
                StreamDemultiplexer._port(layer.sport),
                StreamDemultiplexer._port(layer.dport),
            )

        if packet.haslayer(udp_layer):
            layer = packet[udp_layer]
            return(
                "UDP",
                StreamDemultiplexer._port(layer.sport),
                StreamDemultiplexer._port(layer.dport),
            )

        if icmp_layer is not None and packet.haslayer(icmp_layer):
            return fallback_protocol, None, None
        return fallback_protocol, None, None


    @staticmethod
    def _port(value: Any) -> int:
        """Validate and convert a Scapy port field."""
        try:
            port = int(value)
        except (TypeError, ValueError) as exc:
            raise StreamDemultiplexingError(f"invalid transport port: {value!r}") from exc
        if not 0 <= port <= 65535:
            raise StreamDemultiplexingError("port must be in between 0 and 65535")
        return port
