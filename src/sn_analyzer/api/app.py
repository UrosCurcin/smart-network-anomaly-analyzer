"""FastAPI application factory for the Smart Network Anomaly Analyzer API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from ..config import AppSettings
from ..storage.alert_repository import AlertRepository
from .routers import alerts, capture, status
from .state import ApiState, CaptureController

logger = logging.getLogger(__name__)

_DEFAULT_DEV_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]


def create_app(settings: AppSettings, *, cors_origins: list[str] | None = None) -> FastAPI:
    """Build the FastAPI application for one resolved configuration.

    Args:
        settings: Resolved configuration; see :func:`sn_analyzer.config.load_settings`.
            The API requires ``storage.database_path`` to be set, since every
            endpoint it offers reads or writes alert history.
        cors_origins: Browser origins allowed to call this API, for a web
            dashboard served from a different origin.  Defaults to permissive
            localhost origins, which suit local development only; pass the
            dashboard's real origin(s) in any other deployment.

    Raises:
        ValueError: If ``storage.database_path`` is not set.
    """
    if settings.storage.database_path is None:
        raise ValueError(
            "the API requires alert storage; set storage.database_path in the "
            "configuration (it cannot be run with --no-db style behavior)"
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Open the shared alert database and capture controller for the app's life.

        FastAPI runs everything before ``yield`` once at startup and everything
        after it once at shutdown, so this is where resources that must outlive
        any single request are created and released.
        """
        repository = AlertRepository(settings.storage.database_path)
        controller = CaptureController(settings, repository, logger=logger)
        app.state.sn_state = ApiState(settings=settings, repository=repository, controller=controller)
        logger.info("API started; alerts stored in %s", repository.location)
        try:
            yield
        finally:
            controller.close()
            repository.close()

    app = FastAPI(
        title="Smart Network Anomaly Analyzer",
        description="Read alert history, control packet capture, and check pipeline status.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins or _DEFAULT_DEV_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(status.router)
    app.include_router(capture.router)
    app.include_router(alerts.router)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        """Send a bare visit to the interactive API documentation."""
        return RedirectResponse(url="/docs")

    return app
