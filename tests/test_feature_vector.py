"""Unit tests for the immutability guarantees of FeatureVector."""

from __future__ import annotations

import numpy as np
import pytest

from sn_analyzer.features.schemas import FeatureVector
from sn_analyzer.ingestion.stream_demux import Endpoint, StreamKey


def _key() -> StreamKey:
    return StreamKey("TCP", Endpoint("10.0.0.1", 1), Endpoint("10.0.0.2", 2))


def test_values_are_copied_and_frozen(base_time) -> None:
    """Later changes to the caller's array must not alter the vector."""
    source = np.array([1.0, 2.0])
    vector = FeatureVector(_key(), base_time, source, ("a", "b"), (1,))

    source[0] = 99.0

    assert vector.values[0] == 1.0
    assert not vector.values.flags.writeable
    with pytest.raises(ValueError):
        vector.values[0] = 5.0


def test_integer_input_is_converted_to_float(base_time) -> None:
    """Values are always stored as floating point."""
    vector = FeatureVector(_key(), base_time, np.array([1, 2]), ("a", "b"), ())

    assert vector.values.dtype.kind == "f"
