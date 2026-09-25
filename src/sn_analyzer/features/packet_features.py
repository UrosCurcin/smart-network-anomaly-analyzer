"""Flow-window feature extraction from Scapy packet envelopes."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

import numpy as np

from ..ingestion.base import PacketEnvelope
from ..ingestion.stream_demux import StreamKey
from .schemas import FeatureVector


class FeatureExtractionError(ValueError):
    """Raised when packet data cannot produce a valid feature observation."""


class FeatureExtractor:
    """Extract stable numerical features from packets in one flow time window.

    The caller is responsible for grouping packets by :class:`StreamKey` and
    choosing the aggregation window.  Features use population variance
    (``ddof=0``), which defines variance as zero for a one-packet window and
    avoids introducing missing values into model input.
    """

    FEATURE_NAMES: tuple[str, ...] = (
        "packet_count",
        "byte_count",
        "ip_packet_ratio",
        "tcp_packet_ratio",
        "udp_packet_ratio",
        "icmp_packet_ratio",
        "tcp_syn_ratio",
        "tcp_ack_ratio",
        "tcp_fin_ratio",
        "tcp_rst_ratio",
        "packet_length_mean",
        "packet_length_variance",
        "inter_arrival_mean_seconds",
        "inter_arrival_variance_seconds",
    )

    def extract_window_features(
        self,
        stream_key: StreamKey,
        packets: Sequence[PacketEnvelope],
        window_end: datetime,
    ) -> FeatureVector:
        """Create one feature vector from packets belonging to a flow window.

        Args:
            stream_key: Canonical flow identity shared by ``packets``.
            packets: Non-empty envelopes from exactly one aggregation window.
            window_end: Timezone-aware end time of that aggregation window.

        Returns:
            A validated :class:`FeatureVector` suitable for scikit-learn or
            PyTorch inference.

        Raises:
            FeatureExtractionError: If the window is empty, contains an
                invalid timestamp, or packets cannot be inspected safely.
        """
        if not packets:
            raise FeatureExtractionError("cannot extract features from an empty window")
        if window_end.tzinfo is None or window_end.utcoffset() is None:
            raise FeatureExtractionError("window_end must be timezone-aware")

        ip_layer, ipv6_layer, tcp_layer, udp_layer, icmp_layer = (
            self._load_scapy_layers()
        )
        ordered_packets = sorted(
            packets,
            key=lambda envelope: (envelope.captured_at_utc, envelope.sequence_id),
        )
        self._validate_window(ordered_packets, window_end)

        packet_lengths: list[float] = []
        timestamps: list[float] = []
        ip_packet_count = 0
        tcp_packet_count = 0
        udp_packet_count = 0
        icmp_packet_count = 0
        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0

        for envelope in ordered_packets:
            packet = envelope.packet
            try:
                packet_lengths.append(float(len(packet)))
                timestamps.append(envelope.captured_at_utc.timestamp())
                has_ip = packet.haslayer(ip_layer) or packet.haslayer(ipv6_layer)
                has_tcp = packet.haslayer(tcp_layer)
                has_udp = packet.haslayer(udp_layer)
                has_icmp = packet.haslayer(icmp_layer)
            except Exception as exc:
                raise FeatureExtractionError(
                    f"unable to inspect packet {envelope.sequence_id}"
                ) from exc

            ip_packet_count += int(has_ip)
            tcp_packet_count += int(has_tcp)
            udp_packet_count += int(has_udp)
            icmp_packet_count += int(has_icmp)

            if has_tcp:
                flags = self._tcp_flags(packet, tcp_layer, envelope.sequence_id)
                syn_count += int(bool(flags & 0x02))
                ack_count += int(bool(flags & 0x10))
                fin_count += int(bool(flags & 0x01))
                rst_count += int(bool(flags & 0x04))

        lengths = np.asarray(packet_lengths, dtype=float)
        inter_arrivals = np.diff(np.asarray(timestamps, dtype=float))
        packet_count = len(ordered_packets)
        tcp_denominator = float(tcp_packet_count)

        values = np.asarray(
            (
                float(packet_count),
                float(lengths.sum()),
                ip_packet_count / packet_count,
                tcp_packet_count / packet_count,
                udp_packet_count / packet_count,
                icmp_packet_count / packet_count,
                syn_count / tcp_denominator if tcp_packet_count else 0.0,
                ack_count / tcp_denominator if tcp_packet_count else 0.0,
                fin_count / tcp_denominator if tcp_packet_count else 0.0,
                rst_count / tcp_denominator if tcp_packet_count else 0.0,
                float(lengths.mean()),
                float(lengths.var()),
                float(inter_arrivals.mean()) if inter_arrivals.size else 0.0,
                float(inter_arrivals.var()) if inter_arrivals.size else 0.0,
            ),
            dtype=float,
        )
        values.flags.writeable = False

        return FeatureVector(
            stream_key=stream_key,
            timestamp=window_end.astimezone(timezone.utc),
            values=values,
            feature_names=self.FEATURE_NAMES,
            packet_ids=tuple(envelope.sequence_id for envelope in ordered_packets),
        )

    @staticmethod
    def _load_scapy_layers() -> tuple[Any, Any, Any, Any, Any]:
        """Load Scapy layers only when feature extraction is actually invoked."""
        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
        except ImportError as exc:
            raise FeatureExtractionError(
                "Scapy is required for packet feature extraction; install the "
                "project's packet-capture dependency."
            ) from exc
        return IP, IPv6, TCP, UDP, ICMP

    @staticmethod
    def _validate_window(
        packets: Sequence[PacketEnvelope], window_end: datetime
    ) -> None:
        """Reject packets whose capture time falls after the declared window."""
        normalized_window_end = window_end.astimezone(timezone.utc)
        for envelope in packets:
            if envelope.captured_at_utc > normalized_window_end:
                raise FeatureExtractionError(
                    f"packet {envelope.sequence_id} occurs after window_end"
                )

    @staticmethod
    def _tcp_flags(packet: Any, tcp_layer: Any, sequence_id: int) -> int:
        """Return a TCP bitmask, with a clear error for malformed flag fields."""
        try:
            return int(packet[tcp_layer].flags)
        except (AttributeError, TypeError, ValueError) as exc:
            raise FeatureExtractionError(
                f"packet {sequence_id} has invalid TCP flags"
            ) from exc
