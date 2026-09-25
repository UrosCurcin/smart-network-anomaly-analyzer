"""Tests for saving the trained model once baseline training completes."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

pytest.importorskip("sklearn")
pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from sn_analyzer.cli import AnalyzerService
from sn_analyzer.ingestion.base import PacketEnvelope
from sn_analyzer.models.isolation_forest import IsolationForestModel


def _feed_baseline(service: AnalyzerService, base_time, *, windows: int, packets_per_window: int) -> None:
    """Send enough distinct-flow traffic to complete baseline training."""
    sequence_id = 0
    for window in range(windows):
        # A different source port per window keeps each window's packets in
        # one flow without waiting on window_duration.
        for _ in range(packets_per_window):
            packet = Ether(type=0x0800) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
                sport=50000 + window, dport=443, flags="A"
            )
            service.process_packet(
                PacketEnvelope(
                    packet=packet,
                    captured_at=base_time + timedelta(milliseconds=sequence_id),
                    source="t",
                    sequence_id=sequence_id,
                )
            )
            sequence_id += 1


def test_model_is_saved_once_baseline_training_completes(
    tmp_path: Path, base_time
) -> None:
    """The default Isolation Forest is written to disk right after it is fit."""
    destination = tmp_path / "models" / "trained.joblib"
    service = AnalyzerService(
        evidence_directory=tmp_path / "evidence",
        window_packet_count=10,
        bootstrap_windows=3,
        model_save_path=destination,
    )

    assert not destination.exists()
    _feed_baseline(service, base_time, windows=3, packets_per_window=10)

    assert destination.is_file()
    assert service.is_ready
    loaded = IsolationForestModel.load(str(destination))
    assert loaded.is_fitted


def test_nothing_is_saved_before_training_completes(tmp_path: Path, base_time) -> None:
    """Partial baseline warm-up must not produce a half-trained artifact."""
    destination = tmp_path / "trained.joblib"
    service = AnalyzerService(
        evidence_directory=tmp_path / "evidence",
        window_packet_count=10,
        bootstrap_windows=5,
        model_save_path=destination,
    )

    _feed_baseline(service, base_time, windows=2, packets_per_window=10)

    assert not destination.exists()
    assert not service.is_ready


def test_no_save_path_means_no_file_is_written(tmp_path: Path, base_time) -> None:
    """Existing behavior (no model_save_path) is unchanged."""
    service = AnalyzerService(
        evidence_directory=tmp_path / "evidence",
        window_packet_count=10,
        bootstrap_windows=3,
    )

    _feed_baseline(service, base_time, windows=3, packets_per_window=10)

    assert service.is_ready
    assert list(tmp_path.glob("*.joblib")) == []


def test_preloaded_models_skip_training_and_are_never_auto_saved(
    tmp_path: Path, base_time, caplog: pytest.LogCaptureFixture
) -> None:
    """Supplying a pre-trained model means there is nothing new to save."""
    destination = tmp_path / "trained.joblib"
    preloaded = IsolationForestModel(n_estimators=5, random_state=1)
    import numpy as np

    preloaded.fit(np.random.default_rng(0).normal(size=(20, 14)))

    with caplog.at_level("WARNING"):
        service = AnalyzerService(
            models={"isolation_forest": preloaded},
            evidence_directory=tmp_path / "evidence",
            model_save_path=destination,
        )

    assert "nothing will be saved" in caplog.text
    _feed_baseline(service, base_time, windows=1, packets_per_window=10)
    assert service.is_ready  # was already ready; never entered baseline training
    assert not destination.exists()


def test_save_failure_is_logged_and_does_not_stop_the_service(
    tmp_path: Path, base_time, caplog: pytest.LogCaptureFixture
) -> None:
    """A bad save path degrades gracefully instead of crashing the pipeline."""
    # A path whose parent cannot be created (an existing file, not a directory).
    blocker = tmp_path / "not_a_directory"
    blocker.write_text("x")
    destination = blocker / "trained.joblib"
    service = AnalyzerService(
        evidence_directory=tmp_path / "evidence",
        window_packet_count=10,
        bootstrap_windows=3,
        model_save_path=destination,
    )

    with caplog.at_level("ERROR"):
        _feed_baseline(service, base_time, windows=3, packets_per_window=10)

    assert service.is_ready  # training itself still succeeded
    assert "Failed to save" in caplog.text


def test_multiple_models_are_saved_with_name_suffixed_paths(tmp_path: Path) -> None:
    """More than one registered model is split into per-model artifact files."""
    import numpy as np

    destination = tmp_path / "trained.joblib"
    service = AnalyzerService(evidence_directory=tmp_path / "evidence")
    first = IsolationForestModel(n_estimators=5, random_state=1)
    second = IsolationForestModel(n_estimators=5, random_state=2)
    baseline = np.random.default_rng(0).normal(size=(20, 3))
    first.fit(baseline)
    second.fit(baseline)
    service._models = {"a": first, "b": second}
    service._model_save_path = destination

    service._save_models()

    a_path = tmp_path / "trained.a.joblib"
    b_path = tmp_path / "trained.b.joblib"
    assert a_path.is_file()
    assert b_path.is_file()
    assert IsolationForestModel.load(str(a_path)).is_fitted
    assert IsolationForestModel.load(str(b_path)).is_fitted
