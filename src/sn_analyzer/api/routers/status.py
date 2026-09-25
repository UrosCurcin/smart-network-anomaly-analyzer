"""Health and capture-status endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..dependencies import get_state
from ..schemas import StatusResponse
from ..state import ApiState

router = APIRouter(tags=["status"])


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness check with no dependencies; suitable for orchestration probes."""
    return {"status": "ok"}


@router.get("/status", response_model=StatusResponse)
def get_capture_status(state: ApiState = Depends(get_state)) -> StatusResponse:
    """Report whether capture is running and the pipeline's current health."""
    return StatusResponse.from_status(state.controller.status())
