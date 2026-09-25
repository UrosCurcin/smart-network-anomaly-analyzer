"""Robustly scaled Isolation Forest anomaly model."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Any, Literal

import numpy as np

from .registry import AnomalyModel


class ModelNotFittedError(RuntimeError):
    """Raised when inference or persistence is attempted before fitting."""


class ModelArtifactError(RuntimeError):
    """Raised when a persisted model artifact is missing or incompatible."""


class IsolationForestModel(AnomalyModel):
    """Isolation Forest model with robust scaling and calibrated anomaly scores.

    The model fits :class:`sklearn.preprocessing.RobustScaler` before the
    forest.  Raw Isolation Forest normality scores are inverted, then passed
    through a sigmoid calibrated from training-score median and spread.  The
    resulting output is normalized to ``[0, 1]`` and increases
    as an observation becomes more anomalous according to the fitted forest.
    """

    _ARTIFACT_VERSION = 2

    def __init__(
        self,
        *,
        n_estimators: int = 300,
        contamination: float | Literal["auto"] = "auto",
        max_samples: int | float | Literal["auto"] = "auto",
        random_state: int | None = 42,
        n_jobs: int | None = None,
        min_score_scale: float = 0.05,
    ) -> None:
        """Configure an unfitted Isolation Forest and its robust scaler.

        Args:
            min_score_scale: Floor applied to the fitted score spread (see
                :meth:`fit`), so a baseline with little internal variety can't
                make the calibration hypersensitive. ``decision_function``
                values are typically within roughly ``[-0.5, 0.5]``, so the
                default of ``0.05`` treats spreads far below that as
                statistical noise from a homogeneous baseline sample rather
                than a real, trustworthy measure of "normal" traffic's
                natural spread.
        """
        if n_estimators <= 0:
            raise ValueError("n_estimators must be greater than zero")
        if isinstance(contamination, float) and not 0.0 < contamination <= 0.5:
            raise ValueError("contamination must be in the interval (0, 0.5]")
        if not np.isfinite(min_score_scale) or min_score_scale <= 0.0:
            raise ValueError("min_score_scale must be finite and greater than zero")

        isolation_forest, robust_scaler = self._load_sklearn_components()
        self._config: dict[str, Any] = {
            "n_estimators": n_estimators,
            "contamination": contamination,
            "max_samples": max_samples,
            "random_state": random_state,
            "n_jobs": n_jobs,
        }
        self._min_score_scale = float(min_score_scale)
        self._scaler: Any = robust_scaler()
        self._forest: Any = isolation_forest(**self._config)
        self._feature_count: int | None = None
        self._score_center: float | None = None
        self._score_scale: float | None = None

    @property
    def is_fitted(self) -> bool:
        """Whether this instance has all learned state needed for scoring."""
        return (
            self._feature_count is not None
            and self._score_center is not None
            and self._score_scale is not None
        )

    @property
    def feature_count(self) -> int | None:
        """Return the trained input width, or ``None`` before fitting."""
        return self._feature_count

    def fit(self, features: np.ndarray) -> "IsolationForestModel":
        """Fit the scaler and forest using a two-dimensional baseline dataset."""
        matrix = self._validate_features(features, operation="fit")
        scaled = self._scaler.fit_transform(matrix)
        self._forest.fit(scaled)

        # ``decision_function`` is high for ordinary traffic and low for
        # anomalies.  Negating it establishes the required direction.
        raw_anomaly_scores = -np.asarray(
            self._forest.decision_function(scaled), dtype=float
        )
        score_center = float(np.median(raw_anomaly_scores))
        lower, upper = np.percentile(raw_anomaly_scores, (25.0, 75.0))
        score_scale = float(upper - lower)
        if not np.isfinite(score_scale) or score_scale <= np.finfo(float).eps:
            score_scale = float(np.std(raw_anomaly_scores))
        if not np.isfinite(score_scale) or score_scale <= np.finfo(float).eps:
            score_scale = 1.0
        # A baseline sample with little genuine internal variety (for example,
        # one dominant, highly repetitive flow) can still produce a technically
        # nonzero but tiny spread here. Dividing by that in `score` would turn
        # ordinary sampling noise into an extreme z-score and saturate the
        # sigmoid to 1.0 for virtually every future observation -- including
        # ones drawn from that same "normal" traffic. Flooring the spread
        # keeps the calibration from being that fragile.
        score_scale = max(score_scale, self._min_score_scale)

        self._feature_count = int(matrix.shape[1])
        self._score_center = score_center
        self._score_scale = score_scale
        return self

    def score(self, features: np.ndarray) -> np.ndarray:
        """Return calibrated scores in ``[0, 1]`` where larger means anomalous."""
        self._require_fitted()
        matrix = self._validate_features(features, operation="score")
        if matrix.shape[1] != self._feature_count:
            raise ValueError(
                "feature width does not match the fitted model: "
                f"expected {self._feature_count}, received {matrix.shape[1]}"
            )

        scaled = self._scaler.transform(matrix)
        raw_anomaly_scores = -np.asarray(
            self._forest.decision_function(scaled), dtype=float
        )
        standardized = (raw_anomaly_scores - self._score_center) / self._score_scale
        return self._sigmoid(standardized)

    def save(self, path: str) -> None:
        """Atomically persist the scaler, forest, and score calibration.

        Model artifacts use Joblib/pickle serialization and must only ever be
        loaded from trusted storage, because deserializing untrusted artifacts
        can execute arbitrary code.
        """
        self._require_fitted()
        artifact_path = Path(path)
        if not artifact_path.name:
            raise ValueError("path must name a model artifact file")
        artifact_path.parent.mkdir(parents=True, exist_ok=True)

        joblib = self._load_joblib()
        payload = {
            "artifact_version": self._ARTIFACT_VERSION,
            "model_type": type(self).__name__,
            "config": self._config,
            "min_score_scale": self._min_score_scale,
            "scaler": self._scaler,
            "forest": self._forest,
            "feature_count": self._feature_count,
            "score_center": self._score_center,
            "score_scale": self._score_scale,
        }

        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=artifact_path.parent,
                prefix=f".{artifact_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = temporary_file.name
            joblib.dump(payload, temporary_path)
            os.replace(temporary_path, artifact_path)
        except Exception as exc:
            raise ModelArtifactError(
                f"failed to save model artifact: {artifact_path}"
            ) from exc
        finally:
            if temporary_path is not None:
                Path(temporary_path).unlink(missing_ok=True)

    @classmethod
    def load(cls, path: str) -> "IsolationForestModel":
        """Load a trusted artifact containing a fitted scaler and forest."""
        artifact_path = Path(path)
        if not artifact_path.is_file():
            raise FileNotFoundError(f"model artifact does not exist: {artifact_path}")

        joblib = cls._load_joblib()
        try:
            payload = joblib.load(artifact_path)
            cls._validate_artifact(payload)
            instance = cls(**payload["config"], min_score_scale=payload["min_score_scale"])
            instance._scaler = payload["scaler"]
            instance._forest = payload["forest"]
            instance._feature_count = int(payload["feature_count"])
            instance._score_center = float(payload["score_center"])
            instance._score_scale = float(payload["score_scale"])
            instance._require_fitted()
            return instance
        except (FileNotFoundError, ModelArtifactError):
            raise
        except Exception as exc:
            raise ModelArtifactError(
                f"failed to load model artifact: {artifact_path}"
            ) from exc

    @staticmethod
    def _validate_features(features: np.ndarray, *, operation: str) -> np.ndarray:
        """Convert and validate finite model input without mutating the caller."""
        try:
            matrix = np.asarray(features, dtype=float)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{operation} features must be numeric") from exc
        if matrix.ndim != 2:
            raise ValueError(
                f"{operation} features must be a 2D array of shape "
                "(observations, features)"
            )
        if matrix.shape[0] == 0 or matrix.shape[1] == 0:
            raise ValueError(f"{operation} features must not be empty")
        if not np.isfinite(matrix).all():
            raise ValueError(f"{operation} features must contain only finite values")
        return matrix

    def _require_fitted(self) -> None:
        """Raise a consistent error when learned state is unavailable."""
        if not self.is_fitted:
            raise ModelNotFittedError("fit the model before scoring or saving it")

    @staticmethod
    def _sigmoid(values: np.ndarray) -> np.ndarray:
        """Compute a numerically stable, strictly increasing score transform."""
        result = np.empty_like(values, dtype=float)
        positive = values >= 0
        result[positive] = 1.0 / (1.0 + np.exp(-values[positive]))
        exponent = np.exp(values[~positive])
        result[~positive] = exponent / (1.0 + exponent)
        return result

    @staticmethod
    def _load_sklearn_components() -> tuple[Any, Any]:
        """Import optional scikit-learn dependencies only for model creation."""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import RobustScaler
        except ImportError as exc:
            raise RuntimeError(
                "scikit-learn is required for IsolationForestModel; install the "
                "project's machine-learning dependency."
            ) from exc
        return IsolationForest, RobustScaler

    @staticmethod
    def _load_joblib() -> Any:
        """Import Joblib lazily for model persistence operations."""
        try:
            import joblib
        except ImportError as exc:
            raise RuntimeError(
                "joblib is required to persist IsolationForestModel artifacts."
            ) from exc
        return joblib

    @classmethod
    def _validate_artifact(cls, payload: Any) -> None:
        """Check artifact shape before assigning deserialized learned state."""
        if not isinstance(payload, dict):
            raise ModelArtifactError("model artifact has an invalid payload")
        required_fields = {
            "artifact_version",
            "model_type",
            "config",
            "min_score_scale",
            "scaler",
            "forest",
            "feature_count",
            "score_center",
            "score_scale",
        }
        missing_fields = required_fields.difference(payload)
        if missing_fields:
            raise ModelArtifactError(
                f"model artifact is missing fields: {sorted(missing_fields)}"
            )
        if payload["artifact_version"] != cls._ARTIFACT_VERSION:
            raise ModelArtifactError("model artifact version is unsupported")
        if payload["model_type"] != cls.__name__:
            raise ModelArtifactError("model artifact is not an IsolationForestModel")
        if not isinstance(payload["config"], dict):
            raise ModelArtifactError("model artifact has an invalid configuration")
        if (
            not isinstance(payload["min_score_scale"], (int, float))
            or not np.isfinite(payload["min_score_scale"])
            or payload["min_score_scale"] <= 0
        ):
            raise ModelArtifactError("model artifact has an invalid min_score_scale")
        if not callable(getattr(payload["scaler"], "transform", None)):
            raise ModelArtifactError("model artifact has an invalid scaler")
        if not callable(getattr(payload["forest"], "decision_function", None)):
            raise ModelArtifactError("model artifact has an invalid forest")
        if not isinstance(payload["feature_count"], int) or payload["feature_count"] <= 0:
            raise ModelArtifactError("model artifact has an invalid feature count")
        if not np.isfinite(payload["score_center"]) or not np.isfinite(
            payload["score_scale"]
        ):
            raise ModelArtifactError("model artifact has invalid score calibration")
        if payload["score_scale"] <= 0:
            raise ModelArtifactError("model artifact score scale must be positive")
