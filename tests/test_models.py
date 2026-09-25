"""Unit tests for robustly scaled Isolation Forest inference and persistence."""

from __future__ import annotations

import numpy as np

from sn_analyzer.models.isolation_forest import IsolationForestModel


def test_isolation_forest_fits_and_returns_bounded_scores() -> None:
    """A fitted model returns one normalized score for each input observation."""
    generator = np.random.default_rng(42)
    baseline = generator.normal(loc=0.0, scale=1.0, size=(64, 4))
    model = IsolationForestModel(n_estimators=25, random_state=42).fit(baseline)

    scores = model.score(np.vstack((baseline[:2], np.array([[12.0, 12.0, 12.0, 12.0]]))))

    assert model.is_fitted
    assert scores.shape == (3,)
    assert np.all(np.isfinite(scores))
    assert np.all((0.0 <= scores) & (scores <= 1.0))
    assert scores[2] > scores[0]


def test_isolation_forest_floors_the_score_scale_for_a_homogeneous_baseline() -> None:
    """A baseline with almost no internal variety must not saturate every score.

    Real traffic naturally varies window to window. A baseline sampled from
    one narrow, highly repetitive pattern (a scripted test capture, or a
    quiet backup job running alone overnight) can end up with an IQR-based
    score spread so small that ordinary sampling noise -- even from that same
    "normal" pattern -- reads as many standard deviations away from it and
    saturates the sigmoid to 1.0. ``min_score_scale`` floors that spread so
    a tight baseline doesn't make the calibration this fragile.
    """
    generator = np.random.default_rng(3)
    base_row = np.array([50.0, 30_000.0, 1.0, 1.0, 0.0, 0.0, 0.1, 0.8, 0.1, 0.0, 650.0, 4_000.0, 0.04, 0.0002])
    baseline = np.tile(base_row, (100, 1)) + generator.normal(scale=1e-6, size=(100, 14))
    held_out = np.tile(base_row, (20, 1)) + generator.normal(scale=1e-6, size=(20, 14))

    floored_model = IsolationForestModel(n_estimators=100, random_state=42).fit(baseline)
    unfloored_model = IsolationForestModel(
        n_estimators=100, random_state=42, min_score_scale=1e-12
    ).fit(baseline)

    floored_scores = floored_model.score(held_out)
    unfloored_scores = unfloored_model.score(held_out)

    assert floored_model._score_scale >= 0.05  # noqa: SLF001 (whitebox on purpose)
    assert np.mean(floored_scores) < np.mean(unfloored_scores)
    assert np.all(floored_scores < 0.95)


def test_isolation_forest_rejects_a_non_positive_min_score_scale() -> None:
    """``min_score_scale`` must stay strictly positive to remain a usable floor."""
    for invalid in (0.0, -0.1, float("nan"), float("inf")):
        try:
            IsolationForestModel(min_score_scale=invalid)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for min_score_scale={invalid!r}")


def test_isolation_forest_save_and_load_preserves_scores(tmp_path) -> None:
    """One Joblib artifact retains both preprocessing and fitted forest state."""
    generator = np.random.default_rng(7)
    baseline = generator.normal(size=(48, 3))
    observations = np.array([[0.0, 0.0, 0.0], [10.0, 10.0, 10.0]])
    model = IsolationForestModel(n_estimators=20, random_state=7).fit(baseline)
    expected_scores = model.score(observations)
    artifact = tmp_path / "isolation-forest.joblib"

    model.save(str(artifact))
    loaded_model = IsolationForestModel.load(str(artifact))

    assert artifact.is_file()
    assert loaded_model.is_fitted
    np.testing.assert_allclose(loaded_model.score(observations), expected_scores)
