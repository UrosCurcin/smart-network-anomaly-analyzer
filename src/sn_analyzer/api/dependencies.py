"""FastAPI dependencies shared by every router."""

from __future__ import annotations

from fastapi import Request

from .state import ApiState


def get_state(request: Request) -> ApiState:
    """Return the application state attached to ``app.state`` at startup.

    Every route handler declares ``state: ApiState = Depends(get_state)``
    instead of importing a global, so the state is explicit in each handler's
    signature and easy to substitute in tests.
    """
    return request.app.state.sn_state
