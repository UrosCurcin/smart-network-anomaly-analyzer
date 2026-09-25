"""Pydantic request/response models: the API's public contract.

These are deliberately separate from the internal domain types in
``sn_analyzer.alerting`` and ``sn_analyzer.features``.  The internal types are
free to change as the pipeline evolves (new features, a different model);
these are a promise to whoever calls the API (a dashboard, a script) about
exactly what shape a response has.  ``AlertOut.from_alert`` is the one place
that bridges the two.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from ..alerting.alert_manager import Alert, Severity
from .state import CaptureStatus


class EndpointOut(BaseModel):
    """One side of a network flow."""

    address: str
    port: int | None = None


class AlertOut(BaseModel):
    """One stored alert, in the shape the API exposes it."""

    alert_id: str
    created_at: datetime
    severity: Severity
    anomaly_score: float
    window_end: datetime
    protocol: str
    endpoint_a: EndpointOut
    endpoint_b: EndpointOut
    suspicious_ips: tuple[str, ...]
    evidence_available: bool
    acknowledged: bool = Field(
        description="Whether an analyst has marked this alert as observed"
    )
    model_scores: dict[str, float]
    contributing_features: list[str]
    feature_names: tuple[str, ...]
    feature_values: list[float]
    packet_ids: tuple[int, ...]

    @classmethod
    def from_alert(cls, alert: Alert) -> "AlertOut":
        """Build the API representation from the internal domain object."""
        observation = alert.result.observation
        key = observation.stream_key
        return cls(
            alert_id=alert.alert_id,
            created_at=alert.created_at,
            severity=alert.severity,
            anomaly_score=alert.result.anomaly_score,
            window_end=observation.timestamp,
            protocol=key.protocol,
            endpoint_a=EndpointOut(address=key.endpoint_a.address, port=key.endpoint_a.port),
            endpoint_b=EndpointOut(address=key.endpoint_b.address, port=key.endpoint_b.port),
            suspicious_ips=alert.suspicious_ips,
            evidence_available=alert.evidence_pcap_path is not None,
            acknowledged=alert.acknowledged,
            model_scores=alert.result.model_scores,
            contributing_features=alert.result.contributing_features,
            feature_names=observation.feature_names,
            # np.ndarray is not JSON-serializable; convert each element to a
            # plain float once, here, rather than at every call site.
            feature_values=[float(value) for value in observation.values],
            packet_ids=observation.packet_ids,
        )


class AlertListResponse(BaseModel):
    """One page of alert history."""

    items: list[AlertOut]
    total: int
    limit: int
    offset: int


class SeverityCounts(BaseModel):
    """Alert counts per severity tier, always including zero counts."""

    low: int
    medium: int
    high: int
    critical: int


class InterfaceOut(BaseModel):
    """One network interface available for live capture."""

    name: str
    description: str
    ip_address: str | None = None


class PcapFileOut(BaseModel):
    """One replayable PCAP/PCAPNG file found in ``capture.pcap_dir``."""

    name: str


class ModelFileOut(BaseModel):
    """One saved model artifact found in ``model.model_dir``."""

    name: str


class StatusResponse(BaseModel):
    """Current state and health of the capture pipeline."""

    state: Literal["idle", "running", "stopping", "failed"]
    source: str | None = Field(
        default=None, description="'interface:<name>' or 'pcap:<path>', when running or last run"
    )
    started_at: datetime | None = None
    error: str | None = Field(
        default=None, description="Set when state is 'failed', naming why the session ended"
    )
    is_ready: bool = Field(
        description="False while a fresh baseline is still being learned from traffic"
    )
    active_flow_count: int
    evicted_flow_count: int = Field(
        description="Flows scored early and dropped because the flow cap was reached"
    )
    threshold: float = Field(description="Anomaly score at or above which an alert is raised")
    model_save_path: str | None = Field(
        default=None,
        description="Where the trained model will be (or was) saved for the current or "
        "most recent session, if model saving is configured or was requested",
    )

    @classmethod
    def from_status(cls, status: CaptureStatus) -> "StatusResponse":
        """Build the API representation from the controller's internal snapshot."""
        return cls(
            state=status.state,
            source=status.source,
            started_at=status.started_at,
            error=status.error,
            is_ready=status.is_ready,
            active_flow_count=status.active_flow_count,
            evicted_flow_count=status.evicted_flow_count,
            threshold=status.threshold,
            model_save_path=status.model_save_path,
        )


class StartCaptureRequest(BaseModel):
    """Body of ``POST /capture/start``.

    Every field is optional and overrides the matching configuration setting
    for this one session only; omitted fields fall back to the loaded config.
    """

    interface: str | None = Field(
        default=None, description="Capture interface; overrides capture.interface"
    )
    pcap: str | None = Field(
        default=None,
        description="PCAP file to replay instead of live capture. A bare filename "
        "(e.g. 'traffic.pcap') is looked up in capture.pcap_dir; see "
        "GET /capture/pcaps for the files available there. A full path also "
        "works, for a file kept elsewhere.",
    )
    bpf: str | None = Field(default=None, description="BPF filter; overrides capture.bpf_filter")
    promiscuous: bool | None = Field(
        default=None, description="Promiscuous mode; overrides capture.promiscuous"
    )
    model_path: str | None = Field(
        default=None,
        description="Load a trusted saved model for this session instead of training a new "
        "baseline; overrides model.path. A bare filename is looked up in model.model_dir; "
        "see GET /capture/models for the files available there.",
    )
    model_save_path: str | None = Field(
        default=None,
        description="Save the trained model once baseline training completes this session; "
        "overrides model.save_path. Ignored when model_path (or model.path) is set, since "
        "then no baseline training runs. A bare filename is saved under model.model_dir.",
    )


class AcknowledgeAlertRequest(BaseModel):
    """Body of ``POST /alerts/{alert_id}/acknowledge``."""

    acknowledged: bool = Field(
        default=True,
        description="True marks the alert observed; false clears a previous mark",
    )


class ClearAlertsResponse(BaseModel):
    """Result of ``DELETE /alerts``."""

    deleted: int = Field(description="Number of alerts removed")
