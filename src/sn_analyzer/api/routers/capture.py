"""Endpoints that list capture interfaces and start/stop a capture session."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status as http_status

from ...ingestion.live_capture import LiveCaptureError, list_capture_interfaces
from ..dependencies import get_state
from ..schemas import InterfaceOut, ModelFileOut, PcapFileOut, StartCaptureRequest, StatusResponse
from ..state import ApiState, CaptureAlreadyRunningError

router = APIRouter(prefix="/capture", tags=["capture"])

_PCAP_SUFFIXES = {".pcap", ".pcapng"}
_MODEL_SUFFIXES = {".joblib"}


@router.get("/interfaces", response_model=list[InterfaceOut])
def get_interfaces() -> list[InterfaceOut]:
    """List capture interfaces Scapy can see on this machine.

    This only enumerates interfaces; it does not check whether the caller is
    authorized to capture on them.
    """
    try:
        interfaces = list_capture_interfaces()
    except LiveCaptureError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    return [
        InterfaceOut(name=iface.name, description=iface.description, ip_address=iface.ip_address)
        for iface in interfaces
    ]


@router.get("/pcaps", response_model=list[PcapFileOut])
def get_available_pcaps(state: ApiState = Depends(get_state)) -> list[PcapFileOut]:
    """List replayable PCAP/PCAPNG files in the configured ``capture.pcap_dir``.

    Lets a caller (the dashboard) offer a picker instead of requiring the
    exact filename to be typed. Returns an empty list, rather than an error,
    when the directory doesn't exist yet.
    """
    pcap_dir = state.settings.capture.pcap_dir
    if not pcap_dir.is_dir():
        return []
    names = sorted(
        entry.name
        for entry in pcap_dir.iterdir()
        if entry.is_file() and entry.suffix.lower() in _PCAP_SUFFIXES
    )
    return [PcapFileOut(name=name) for name in names]


@router.get("/models", response_model=list[ModelFileOut])
def get_available_models(state: ApiState = Depends(get_state)) -> list[ModelFileOut]:
    """List saved model artifacts (``*.joblib``) in the configured ``model.model_dir``.

    Lets a caller (the dashboard) pick a previously saved model to load
    instead of retraining a baseline from scratch every session. Returns an
    empty list, rather than an error, when the directory doesn't exist yet
    (e.g. nothing has been saved there).
    """
    model_dir = state.settings.model.model_dir
    if not model_dir.is_dir():
        return []
    names = sorted(
        entry.name
        for entry in model_dir.iterdir()
        if entry.is_file() and entry.suffix.lower() in _MODEL_SUFFIXES
    )
    return [ModelFileOut(name=name) for name in names]


@router.post(
    "/start", response_model=StatusResponse, status_code=http_status.HTTP_202_ACCEPTED
)
def start_capture(
    request: StartCaptureRequest, state: ApiState = Depends(get_state)
) -> StatusResponse:
    """Start one capture session (a live interface or a PCAP replay).

    Returns immediately; capture runs in the background.  Poll ``GET /status``
    to see when baseline training finishes (``is_ready``) or if the session
    fails (``state: "failed"``, with ``error`` set).
    """
    try:
        state.controller.start(
            interface=request.interface,
            pcap=request.pcap,
            bpf=request.bpf,
            promiscuous=request.promiscuous,
            model_path=request.model_path,
            model_save_path=request.model_save_path,
        )
    except CaptureAlreadyRunningError as exc:
        raise HTTPException(status_code=http_status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except (OSError, RuntimeError) as exc:
        # Covers a missing PCAP file and a model artifact that fails to load.
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return StatusResponse.from_status(state.controller.status())


@router.post("/stop", response_model=StatusResponse)
def stop_capture(state: ApiState = Depends(get_state)) -> StatusResponse:
    """Stop the running capture session. Safe to call when nothing is running."""
    state.controller.stop()
    return StatusResponse.from_status(state.controller.status())
