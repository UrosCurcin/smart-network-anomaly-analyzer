"""Destinations that receive alerts after :class:`AlertManager` creates them."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # Avoids a runtime import cycle with ``alert_manager``.
    from .alert_manager import Alert


class AlertSink(ABC):
    """Receiver of alerts, such as a database, a message queue, or a webhook.

    ``publish`` runs synchronously on the analysis thread, so implementations
    should be quick.  Exceptions are caught and logged by ``AlertManager``: a
    failing sink never loses the alert for other sinks or crashes monitoring.
    """

    @abstractmethod
    def publish(self, alert: "Alert") -> None:
        """Deliver one newly created alert."""
        raise NotImplementedError
