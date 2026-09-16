"""Application factory and wiring.

A factory rather than a module-level ``app = FastAPI()``: tests build an app with
their own settings and database, and a future CLI can construct one without importing
production configuration as a side effect of an import statement.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from promptsentinel import __version__
from promptsentinel.api.routes import health, probes, scans
from promptsentinel.config import Settings, get_settings
from promptsentinel.core.errors import AuthorizationError, ConfigurationError, TargetError
from promptsentinel.db.session import Database
from promptsentinel.jobs.queue import InProcessJobQueue
from promptsentinel.jobs.worker import ScanWorker
from promptsentinel.probes.registry import REGISTRY, ProbeRegistry

logger = logging.getLogger(__name__)

DESCRIPTION = """
Automated security testing for **deployed** LLM applications.

PromptSentinel probes the application you shipped -- its system prompt, retrieval
pipeline and tool wiring -- not the base model in the abstract.

Findings are confidence-tiered:

* **confirmed** -- a probe obtained verifiable proof, such as a seeded canary value
  returned verbatim or a disallowed tool actually invoked.
* **suspicious** -- a heuristic fired but there is no hard proof. Needs a human.

A suspicious finding is never promoted to confirmed.

### Authorization is mandatory

Every scan must carry an attestation that you own or are authorized to test the
target. Requests without one are refused with 403 before anything is queued.
"""


def create_app(
    *,
    settings: Settings | None = None,
    database: Database | None = None,
    registry: ProbeRegistry = REGISTRY,
) -> FastAPI:
    """Build the application. Injected arguments exist so tests can substitute pieces."""
    resolved_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = database or Database(resolved_settings.database_url)
        if resolved_settings.auto_create_schema:
            await db.create_all()
        else:
            logger.info("auto_create_schema disabled; expecting `alembic upgrade head`")
        registry.discover()

        worker = ScanWorker(db, resolved_settings, registry=registry)
        queue = InProcessJobQueue(
            worker.execute, max_concurrent=resolved_settings.max_concurrent_scans
        )

        app.state.settings = resolved_settings
        app.state.database = db
        app.state.registry = registry
        app.state.queue = queue
        logger.info("promptsentinel %s ready with %d probes", __version__, len(registry.all()))

        try:
            yield
        finally:
            # Let running scans finish before tearing down the engine, otherwise a
            # scan's final write lands on a disposed connection pool.
            await queue.aclose()
            if database is None:
                await db.dispose()

    app = FastAPI(
        title="PromptSentinel",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
        openapi_tags=[
            {"name": "scans", "description": "Submit scans and retrieve reports."},
            {"name": "probes", "description": "Discover available attack techniques."},
            {"name": "health", "description": "Liveness and readiness."},
        ],
    )

    _register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(probes.router)
    app.include_router(scans.router)
    return app


def _register_exception_handlers(app: FastAPI) -> None:
    """Map domain errors to HTTP once, centrally.

    Routes then raise domain exceptions and stay free of status codes. The
    authorization handler is the important one: it guarantees that every path which
    fails the gate produces the same 403, including paths added later by someone who
    has not read this file.
    """

    @app.exception_handler(AuthorizationError)
    async def _authorization(_: Request, exc: AuthorizationError) -> JSONResponse:
        logger.warning("refused unauthorized scan request: %s", exc)
        return JSONResponse(
            status_code=403,
            content={"error": "authorization_required", "detail": str(exc)},
        )

    @app.exception_handler(ConfigurationError)
    async def _configuration(_: Request, exc: ConfigurationError) -> JSONResponse:
        return JSONResponse(
            status_code=400, content={"error": "invalid_request", "detail": str(exc)}
        )

    @app.exception_handler(TargetError)
    async def _target(_: Request, exc: TargetError) -> JSONResponse:
        return JSONResponse(
            status_code=502, content={"error": "target_unreachable", "detail": str(exc)}
        )


app = create_app()
"""ASGI entry point: ``uvicorn promptsentinel.api.app:app``."""
