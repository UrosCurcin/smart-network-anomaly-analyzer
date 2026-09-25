"""Abstract contracts for anomaly-detection model implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
import numpy as np


class AnomalyModel(ABC):
    """Common interface for trainable, persistable anomaly-detection models.

    Implementations accept two-dimensional arrays shaped
    ``(observations, features)``.  Their ``score`` methods must return one
    score per observation, with larger values indicating greater anomaly risk.
    """

    @abstractmethod
    def fit(self, features: np.ndarray) -> "AnomalyModel":
        """Fit the model and any required preprocessing on baseline features."""
        raise NotImplementedError

    @abstractmethod
    def score(self, features: np.ndarray) -> np.ndarray:
        """Return one normalized, higher-is-more-anomalous score per row."""
        raise NotImplementedError

    @abstractmethod
    def save(self, path: str) -> None:
        """Persist all learned state required for later inference."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def load(cls, path: str) -> "AnomalyModel":
        """Load one previously persisted model artifact from a trusted path."""
        raise NotImplementedError
