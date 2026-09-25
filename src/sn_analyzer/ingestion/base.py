from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from types import MappingProxyType
from datetime import timezone
from threading import RLock

class CapturedState(str, Enum):
    """Lifecycle states exposed by a packet capture source."""
    CREATED = "created"
    RUNNING = "running"
    STOPPED = "stopped"
    STOPPING = "stopping"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class PacketEnvelope:
    """A captured packet and immutable metadata used by pipeline stages.

    Attributes:
        packet: Native packet object produced by the capture adapter.  It is
            intentionally typed as ``Any`` so Scapy and PyShark adapters can
            coexist without introducing an optional dependency here.
        captured_at: Time at which the packet was observed or recorded in the
            PCAP.  Timestamps must be timezone-aware, preferably UTC.
        source: Stable description of the packet origin, such as an interface
            name or an absolute PCAP path.
        sequence_id: Monotonically increasing sequence number scoped to a
            single packet source instance.
        metadata: Adapter-specific, JSON-serializable metadata.  It is copied
            into an immutable mapping to prevent mutation after ingestion.
    """

    packet: Any
    captured_at: datetime
    source: str #Live or PCAP path/reference
    sequence_id: int
    metadata: Mapping[str, str | int | float | bool | None] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        """Validate cross-adapter invariants at the system boundary."""
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("captured_at must be timezone-aware")
        if not self.source or not self.source.strip():
            raise ValueError("source must be non-empty string")
        if self.sequence_id < 0:
            raise ValueError("sequence_id must be non-negative")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @property
    def captured_at_utc(self) -> datetime:
        """Return the capture timestamp normalized to UTC."""
        return self.captured_at.astimezone(timezone.utc)


class PacketSource(AbstractContextManager["PacketSource"]):

    """Abstract, safely stoppable producer of :class:`PacketEnvelope` values.

    Implementations must call ``_mark_running()`` before yielding a packet,
    check ``stop_requested`` in their producer loop, and call ``_mark_stopped``
    from cleanup.  This creates a uniform lifecycle for live capture and PCAP
    replay without imposing a capture-library dependency on consumers.

    Attributes:
        is_live: ``True`` for sources whose packet timestamps track the wall
            clock (interface capture).  Consumers use it to decide whether
            wall-clock housekeeping, such as flushing quiet flows, is valid.
            Offline replay leaves it ``False`` because its timestamps are
            historical.
    """

    is_live: bool = False

    def __init__(self) -> None:
        """Create a source in the ``CREATED`` state."""
        self._state = CapturedState.CREATED
        self._lock = RLock()

    @property
    def state(self) -> CapturedState:
        """Return the current lifecycle state in a thread-safe manner."""
        with self._lock:
            return self._state

    @property
    def stop_requested(self) -> bool:
        """Whether a consumer has requested that capture stop gracefully."""
        return self.state in {
            CapturedState.STOPPING,
            CapturedState.STOPPED,
            CapturedState.FAILED,
        }


    @abstractmethod
    def packets(self) -> Iterator[PacketEnvelope]:
        """Yield packets until input is exhausted, stopped, or an error occurs.

        Implementations should release capture resources in a ``finally``
        block and must not yield envelopes after ``stop_requested`` becomes
        true.  Capture-specific exceptions may be raised after marking the
        source as failed.
        """

        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """Request a prompt, idempotent, and graceful shutdown of the source."""
        raise NotImplementedError


    def __enter__(self) -> "PacketSource":
        """Return this source for use in a context-manager capture session."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Ensure a source receives a shutdown request on context exit."""
        self.stop()

    def _mark_running(self) -> None:
        """Transition to running; intended for use by concrete sources only."""
        with self._lock:
            if self._state is CapturedState.CREATED:
                self._state = CapturedState.RUNNING
                return
            if self._state is not CapturedState.RUNNING:
                raise RuntimeError(f"cannot start source in {self._state.value} state")

    def _mark_stopping(self) -> None:
        """Transition to stopping without overriding a terminal state."""
        with self._lock:
            if self._state in {CapturedState.CREATED, CapturedState.RUNNING}:
                self._state = CapturedState.STOPPING

    def _mark_stopped(self) -> None:
        """Mark cleanup complete unless the source has already failed."""
        with self._lock:
            if self._state is not CapturedState.FAILED:
                self._state = CapturedState.STOPPED

    def _mark_failed(self) -> None:
        """Record a terminal failure before propagating a capture exception."""
        with self._lock:
            self._state = CapturedState.FAILED