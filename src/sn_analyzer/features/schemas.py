"""Immutable feature schemas shared by extraction, training, and inference."""



from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping

import numpy as np

from ..ingestion.stream_demux import StreamKey


@dataclass
class FeatureVector:
    """A validated numerical observation describing one network-flow window.

    Attributes:
        stream_key: Canonical bidirectional identity of the flow that produced
            this observation.
        timestamp: Timezone-aware end time of the feature aggregation window.
        values: One-dimensional, finite, floating-point NumPy array.  The
            constructor copies it and marks it read-only to preserve the
            immutability promised by this schema.
        feature_names: Ordered names corresponding one-to-one with ``values``.
            They make model scores explainable and enforce a stable schema.
        packet_ids: Ordered, unique source sequence IDs for packets contributing
            to this vector.  They allow anomalous observations to be traced
            back to exact packets for evidence-PCAP generation.
    """


    stream_key: StreamKey
    timestamp: datetime
    values: np.ndarray
    feature_names: tuple[str, ...]
    packet_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        """Validate the schema and defensively freeze mutable input values."""
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("Timestamp must be timezone aware.")
        # Always copy so later changes to the caller's array cannot alter this
        # vector, then freeze the private copy (np.asarray would share memory).
        values = np.array(self.values, dtype=float, copy=True)
        if values.ndim != 1:
            raise ValueError("values must be onedimensional array.")
        if values.size == 0:
            raise ValueError("values must contain at least one feature.")
        if not np.isfinite(values).all():
            raise ValueError("values must be finite floating-point values.")

        feature_names = tuple(self.feature_names)
        if len(feature_names) != values.size:
            raise ValueError("feature_names must match values size.")
        if any(not isinstance(name, str) or not name.strip() for name in feature_names):
            raise ValueError("feature_names must contain non-empty strings.")
        if len(set(feature_names)) != len(feature_names):
            raise ValueError("feature_names must be unique.")

        packet_ids = tuple(self.packet_ids)
        if any(not isinstance(packet_id, int) or isinstance(packet_id, bool) for packet_id in packet_ids):
            raise ValueError("packet_ids must contain integers.")
        if any(packet_id < 0 for packet_id in packet_ids):
            raise ValueError("packet_ids must contain non-negative integers.")
        if len(set(packet_ids)) != len(packet_ids):
            raise ValueError("packet_ids must be unique.")


        values.flags.writeable = False

        object.__setattr__(self, "timestamp", self.timestamp.astimezone(timezone.utc))
        object.__setattr__(self, "values", values)
        object.__setattr__(self, "feature_names", feature_names)
        object.__setattr__(self, "packet_ids", packet_ids)


    @property
    def feature_count(self) -> int:
        """Return the number of numerical features in this observation."""
        return int(self.values.size)

    @property
    def feature_map(self) -> Mapping[str, float]:
        """Return an immutable mapping from feature name to feature value."""
        return MappingProxyType(
            {
            name: float(value)
            for name, value in zip(self.feature_names, self.values, strict = True)
            }
        )


