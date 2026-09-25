"""Endpoints for reading, acknowledging, and clearing stored alert history."""

from __future__ import annotations

from datetime import datetime
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status as http_status
from fastapi.responses import FileResponse

from ...storage.alert_repository import AlertRepositoryError
from ..dependencies import get_state
from ..schemas import (
    AcknowledgeAlertRequest,
    AlertListResponse,
    AlertOut,
    ClearAlertsResponse,
    SeverityCounts,
)
from ..state import ApiState

router = APIRouter(prefix="/alerts", tags=["alerts"])
logger = logging.getLogger(__name__)


@router.get("", response_model=AlertListResponse)
def list_alerts(
    state: ApiState = Depends(get_state),
    limit: int = Query(50, ge=1, le=1000, description="Page size"),
    offset: int = Query(0, ge=0, description="Number of matching alerts to skip"),
    severity: str | None = Query(
        None, pattern="^(low|medium|high|critical)$", description="Filter by severity"
    ),
    ip: str | None = Query(None, description="Only alerts whose flow involves this IP address"),
    since: datetime | None = Query(
        None, description="Only alerts created at or after this timezone-aware time"
    ),
    until: datetime | None = Query(
        None, description="Only alerts created strictly before this timezone-aware time"
    ),
    acknowledged: bool | None = Query(
        None, description="Filter by whether the alert has been marked observed"
    ),
) -> AlertListResponse:
    """Return a filtered, paginated page of alert history, newest first."""
    try:
        items = state.repository.list_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            ip=ip,
            since=since,
            until=until,
            acknowledged=acknowledged,
        )
        total = state.repository.count_alerts(
            severity=severity, ip=ip, since=since, until=until, acknowledged=acknowledged
        )
    except ValueError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except AlertRepositoryError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc
    return AlertListResponse(
        items=[AlertOut.from_alert(alert) for alert in items], total=total, limit=limit, offset=offset
    )


@router.get("/stats", response_model=SeverityCounts)
def alert_stats(state: ApiState = Depends(get_state)) -> SeverityCounts:
    """Return alert counts for every severity, for a dashboard summary tile."""
    return SeverityCounts(**state.repository.count_by_severity())


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: str, state: ApiState = Depends(get_state)) -> AlertOut:
    """Return one alert by id."""
    alert = state.repository.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="alert not found")
    return AlertOut.from_alert(alert)


@router.get("/{alert_id}/evidence")
def get_alert_evidence(alert_id: str, state: ApiState = Depends(get_state)) -> FileResponse:
    """Download the evidence PCAP captured for one alert, if it has one."""
    alert = state.repository.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="alert not found")
    if alert.evidence_pcap_path is None:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="no evidence was retained for this alert",
        )

    evidence_dir = state.settings.storage.evidence_dir.expanduser().resolve()
    evidence_path = Path(alert.evidence_pcap_path).resolve()
    if evidence_path != evidence_dir and evidence_dir not in evidence_path.parents:
        # Defense in depth: a database row should never point outside the
        # configured evidence directory, but never trust stored data blindly
        # when it is about to be turned into a file path on disk.
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="stored evidence path is outside the configured evidence directory",
        )
    if not evidence_path.is_file():
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND, detail="evidence file is missing on disk"
        )
    return FileResponse(
        evidence_path, media_type="application/vnd.tcpdump.pcap", filename=f"{alert_id}.pcap"
    )


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(
    alert_id: str,
    body: AcknowledgeAlertRequest = AcknowledgeAlertRequest(),
    state: ApiState = Depends(get_state),
) -> AlertOut:
    """Mark one alert as observed, or clear a previous mark.

    The evidence PCAP (if any) is left untouched; this only records that an
    analyst has looked at the alert, so it can be told apart from ones that
    still need attention.
    """
    try:
        updated = state.repository.set_acknowledged(alert_id, body.acknowledged)
    except AlertRepositoryError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc
    if not updated:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="alert not found")

    alert = state.repository.get_alert(alert_id)
    if alert is None:  # pragma: no cover - a concurrent delete between the two calls above
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="alert not found")
    return AlertOut.from_alert(alert)


@router.delete("/{alert_id}", status_code=http_status.HTTP_204_NO_CONTENT)
def delete_alert(alert_id: str, state: ApiState = Depends(get_state)) -> None:
    """Delete one alert and remove its evidence PCAP, if it has one.

    Once inspected, an alert's evidence file is often the only reason to keep
    it around; deleting the row also deletes that file so nothing has to be
    cleaned up by hand on disk.
    """
    alert = state.repository.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="alert not found")
    try:
        state.repository.delete_alert(alert_id)
    except AlertRepositoryError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc
    if alert.evidence_pcap_path is not None:
        _remove_evidence_file(state, alert.evidence_pcap_path)


@router.delete("", response_model=ClearAlertsResponse)
def clear_alerts(state: ApiState = Depends(get_state)) -> ClearAlertsResponse:
    """Delete every stored alert and remove all of their evidence PCAPs.

    Meant for emptying the alerts page once everything in it has been
    reviewed, rather than keeping every past evidence artifact around
    indefinitely. This cannot be undone.
    """
    try:
        deleted, evidence_paths = state.repository.clear_alerts()
    except AlertRepositoryError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc
    for evidence_pcap_path in evidence_paths:
        _remove_evidence_file(state, evidence_pcap_path)
    return ClearAlertsResponse(deleted=deleted)


def _remove_evidence_file(state: ApiState, evidence_pcap_path: str) -> None:
    """Best-effort removal of one evidence PCAP; failures are logged, not raised.

    The database row is the record the caller actually asked to delete. If
    the file is already gone, locked, or (defensively) resolves outside the
    configured evidence directory, that must not turn a delete into an error.
    """
    evidence_dir = state.settings.storage.evidence_dir.expanduser().resolve()
    try:
        evidence_path = Path(evidence_pcap_path).resolve()
        if evidence_path != evidence_dir and evidence_dir not in evidence_path.parents:
            logger.warning(
                "Refusing to delete evidence file outside the configured directory: %s",
                evidence_pcap_path,
            )
            return
        evidence_path.unlink(missing_ok=True)
    except OSError:
        logger.exception("Failed to remove evidence file %s", evidence_pcap_path)
