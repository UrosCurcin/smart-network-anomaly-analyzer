"""Model-ensemble inference and baseline-based anomaly explanations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import numpy as np

from ..features.schemas import FeatureVector
from ..models.registry import AnomalyModel


class InferenceError(RuntimeError):
    """Raised when an inference model returns an invalid or unusable score."""


@dataclass(frozen=True, slots=True)
class InferenceResult:
    """Immutable result of evaluating one flow-window observation.

    Attributes:
        observation: The original feature vector supplied to the engine.
        anomaly_score: Weighted ensemble score in the inclusive range ``[0, 1]``.
            Larger values represent more anomalous traffic.
        is_anomalous: Whether ``anomaly_score`` meets or exceeds the configured
            decision threshold.
        model_scores: Per-model normalized scores keyed by registered model name.
        contributing_features: Feature names with the largest absolute baseline
            deviations.  It is empty when no baseline statistics were supplied.
    """

    observation: FeatureVector
    anomaly_score: float
    is_anomalous: bool
    model_scores: dict[str, float]
    contributing_features: list[str]

    def __post_init__(self) -> None:
        """Validate primitive output fields and detach mutable caller containers."""
        if not np.isfinite(self.anomaly_score) or not 0.0 <= self.anomaly_score <= 1.0:
            raise ValueError("anomaly_score must be finite and in the range [0, 1]")
        if not isinstance(self.is_anomalous, bool):
            raise ValueError("is_anomalous must be a bool")

        normalized_scores: dict[str, float] = {}
        for name, score in self.model_scores.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("model_scores keys must be non-empty strings")
            numeric_score = float(score)
            if not np.isfinite(numeric_score) or not 0.0 <= numeric_score <= 1.0:
                raise ValueError("model_scores must be finite values in the range [0, 1]")
            normalized_scores[name] = numeric_score

        contributors = list(self.contributing_features)
        if any(not isinstance(name, str) or not name.strip() for name in contributors):
            raise ValueError("contributing_features must contain non-empty strings")

        object.__setattr__(self, "anomaly_score", float(self.anomaly_score))
        object.__setattr__(self, "model_scores", normalized_scores)
        object.__setattr__(self, "contributing_features", contributors)


class InferenceEngine:
    """Combine normalized anomaly models into one decision for each observation.

    Each registered model must return exactly one finite score in ``[0, 1]`` for
    a single-row feature matrix.  Input weights are normalized once during
    construction, so callers may provide any non-negative relative weights.
    """

    def __init__(
        self,
        models: Mapping[str, AnomalyModel],
        model_weights: Mapping[str, float],
        threshold: float,
        *,
        baseline_mean: np.ndarray | None = None,
        baseline_variance: np.ndarray | None = None,
        max_contributing_features: int = 5,
    ) -> None:
        """Configure models, their ensemble weights, and decision threshold.

        Args:
            models: Named, already-fitted anomaly models.
            model_weights: One non-negative relative weight for every model.
            threshold: Inclusive anomaly decision threshold from 0 to 1.
            baseline_mean: Optional mean vector for simple z-score explanations.
            baseline_variance: Optional variance vector paired with the mean.
            max_contributing_features: Maximum feature names returned as an
                explanation for one result.
        """
        self._models = self._validate_models(models)
        self._weights = self._normalize_weights(model_weights, self._models)

        numeric_threshold = float(threshold)
        if not np.isfinite(numeric_threshold) or not 0.0 <= numeric_threshold <= 1.0:
            raise ValueError("threshold must be finite and in the range [0, 1]")
        if max_contributing_features <= 0:
            raise ValueError("max_contributing_features must be greater than zero")

        self._threshold = numeric_threshold
        self._max_contributing_features = max_contributing_features
        self._baseline_mean, self._baseline_variance = self._prepare_baseline(
            baseline_mean, baseline_variance
        )

    @property
    def threshold(self) -> float:
        """Return the inclusive score threshold used for anomaly decisions."""
        return self._threshold

    def evaluate(self, observation: FeatureVector) -> InferenceResult:
        """Score one feature vector with every model and combine the results.

        Raises:
            InferenceError: If a registered model fails or produces an invalid
                score shape or range.
            ValueError: If supplied baseline statistics do not match the
                observation's feature schema.
        """
        matrix = observation.values.reshape(1, -1)
        model_scores: dict[str, float] = {}

        for name, model in self._models.items():
            try:
                raw_scores = np.asarray(model.score(matrix), dtype=float)
            except Exception as exc:
                raise InferenceError(f"model {name!r} failed during scoring") from exc

            if raw_scores.shape != (1,):
                raise InferenceError(
                    f"model {name!r} returned shape {raw_scores.shape}; expected (1,)"
                )
            score = float(raw_scores[0])
            if not np.isfinite(score) or not 0.0 <= score <= 1.0:
                raise InferenceError(
                    f"model {name!r} returned a score outside the range [0, 1]"
                )
            model_scores[name] = score

        ensemble_score = float(
            sum(self._weights[name] * score for name, score in model_scores.items())
        )
        return InferenceResult(
            observation=observation,
            anomaly_score=ensemble_score,
            is_anomalous=ensemble_score >= self._threshold,
            model_scores=model_scores,
            contributing_features=self._contributing_features(observation),
        )

    def _contributing_features(self, observation: FeatureVector) -> list[str]:
        """Return top absolute z-score deviations when baseline data is available."""
        if self._baseline_mean is None or self._baseline_variance is None:
            return []
        if observation.feature_count != self._baseline_mean.size:
            raise ValueError(
                "baseline feature width does not match the observation: "
                f"expected {self._baseline_mean.size}, received "
                f"{observation.feature_count}"
            )

        differences = np.abs(observation.values - self._baseline_mean)
        standard_deviations = np.sqrt(self._baseline_variance)
        deviations = np.divide(
            differences,
            standard_deviations,
            out=np.where(differences == 0.0, 0.0, np.inf),
            where=standard_deviations > 0.0,
        )
        ordered_indices = np.argsort(-deviations, kind="stable")
        return [
            observation.feature_names[index]
            for index in ordered_indices[: self._max_contributing_features]
            if deviations[index] > 0.0
        ]

    @staticmethod
    def _validate_models(models: Mapping[str, AnomalyModel]) -> dict[str, AnomalyModel]:
        """Ensure the engine has named model instances before evaluation begins."""
        if not models:
            raise ValueError("at least one anomaly model must be registered")
        validated: dict[str, AnomalyModel] = {}
        for name, model in models.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("model names must be non-empty strings")
            if not isinstance(model, AnomalyModel):
                raise TypeError(f"model {name!r} must implement AnomalyModel")
            validated[name] = model
        return validated

    @staticmethod
    def _normalize_weights(
        weights: Mapping[str, float], models: Mapping[str, AnomalyModel]
    ) -> dict[str, float]:
        """Validate exact model coverage and convert relative weights to fractions."""
        model_names = set(models)
        weight_names = set(weights)
        if model_names != weight_names:
            missing = sorted(model_names.difference(weight_names))
            unexpected = sorted(weight_names.difference(model_names))
            details: list[str] = []
            if missing:
                details.append(f"missing weights for {missing}")
            if unexpected:
                details.append(f"weights supplied for unknown models {unexpected}")
            raise ValueError("model weights do not match registered models: " + "; ".join(details))

        numeric_weights: dict[str, float] = {}
        for name, weight in weights.items():
            numeric_weight = float(weight)
            if not np.isfinite(numeric_weight) or numeric_weight < 0.0:
                raise ValueError("model weights must be finite and non-negative")
            numeric_weights[name] = numeric_weight

        total_weight = sum(numeric_weights.values())
        if total_weight <= 0.0:
            raise ValueError("at least one model weight must be greater than zero")
        return {name: weight / total_weight for name, weight in numeric_weights.items()}

    @staticmethod
    def _prepare_baseline(
        baseline_mean: np.ndarray | None, baseline_variance: np.ndarray | None
    ) -> tuple[np.ndarray | None, np.ndarray | None]:
        """Validate and freeze optional baseline statistics for explanations."""
        if baseline_mean is None and baseline_variance is None:
            return None, None
        if baseline_mean is None or baseline_variance is None:
            raise ValueError("baseline_mean and baseline_variance must be provided together")

        mean = np.asarray(baseline_mean, dtype=float)
        variance = np.asarray(baseline_variance, dtype=float)
        if mean.ndim != 1 or variance.ndim != 1 or mean.size == 0:
            raise ValueError("baseline statistics must be non-empty one-dimensional arrays")
        if mean.shape != variance.shape:
            raise ValueError("baseline_mean and baseline_variance must have matching shapes")
        if not np.isfinite(mean).all() or not np.isfinite(variance).all():
            raise ValueError("baseline statistics must contain only finite values")
        if np.any(variance < 0.0):
            raise ValueError("baseline_variance must not contain negative values")

        immutable_mean = np.array(mean, dtype=float, copy=True)
        immutable_variance = np.array(variance, dtype=float, copy=True)
        immutable_mean.setflags(write=False)
        immutable_variance.setflags(write=False)
        return immutable_mean, immutable_variance
