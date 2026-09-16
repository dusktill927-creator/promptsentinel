"""Application factory and wiring.

A factory rather than a module-level ``app = FastAPI()``: tests build an app with
their own settings and database, and a future CLI can construct one without importing
production configuration as a side effect of an import statement.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from promptsentinel import __version__
from promptsentinel.api.routes import dashboard, health, probes, scans
from promptsentinel.api.security import require_api_key
from promptsentinel.config import Settings, get_settings
from promptsentinel.core.errors import AuthorizationError, ConfigurationError, TargetError
from promptsentinel.db.session import Database
from promptsentinel.jobs.queue import InProcessJobQueue, JobQueue
from promptsentinel.jobs.worker import ScanWorker
from promptsentinel.probes.registry import REGISTRY, ProbeRegistry
from promptsentinel.secrets import InMemorySecretStore, SecretStore

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

### Authentication

Every `/v1` endpoint requires an API key, sent as `Authorization: Bearer <key>` or
`X-API-Key: <key>`. Health endpoints are open.

### Authorization is mandatory

Every scan must carry an attestation that you own or are authorized to test the
target. Requests without one are refused with 403 before anything is queued.
"""


def create_app(
    *,
    settings: Settings | None = None,
    database: Database | None = None,
    registry: ProbeRegistry = REGISTRY,
    secret_store: SecretStore | None = None,
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

        store, queue = _build_backends(resolved_settings, db, registry, secret_store)

        _check_authentication(resolved_settings)

        app.state.settings = resolved_settings
        app.state.database = db
        app.state.registry = registry
        app.state.queue = queue
        app.state.secrets = store
        logger.info("promptsentinel %s ready with %d probes", __version__, len(registry.all()))

        try:
            yield
        finally:
            # Let running scans finish before tearing down the engine, otherwise a
            # scan's final write lands on a disposed connection pool.
            await queue.aclose()
            await store.aclose()
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
    # Health is unguarded on purpose: a liveness probe that needs a credential reports
    # an outage every time that credential rotates.
    app.include_router(health.router)
    app.include_router(probes.router, dependencies=[Depends(require_api_key)])
    app.include_router(scans.router, dependencies=[Depends(require_api_key)])
    if resolved_settings.enable_dashboard:
        # Not behind require_api_key: a browser cannot send that header. It does its own
        # check, accepting the same key from a cookie it sets at sign-in.
        app.include_router(dashboard.router)
    return app


def _build_backends(
    settings: Settings,
    database: Database,
    registry: ProbeRegistry,
    override: SecretStore | None,
) -> tuple[SecretStore, JobQueue]:
    """Pick the queue and the secret store together.

    They are chosen from one setting because they have to agree: a Redis queue with a
    process-local secret store would fail every scan at credential lookup, and a
    misconfiguration that only shows up once a real scan runs is the expensive kind.
    Setting ``redis_url`` moves both.
    """
    if settings.distributed:
        assert settings.redis_url is not None
        queue, secret_store = _redis_backends(settings.redis_url)
        store: SecretStore = override or secret_store
        logger.info("distributed mode: scans run in a separate worker process")
        return store, queue

    store = override or InMemorySecretStore()
    scan_worker = ScanWorker(database, settings, store, registry=registry)
    return store, InProcessJobQueue(
        scan_worker.execute, max_concurrent=settings.max_concurrent_scans
    )


def _redis_backends(url: str) -> tuple[JobQueue, SecretStore]:
    """Import the Redis backends only when they are actually going to be used.

    Imported at module scope they would make ``arq`` and ``redis`` mandatory, which
    defeats the point of declaring them as extras -- ``pip install promptsentinel``
    followed by starting the API would fail on an import for a mode the operator never
    asked for. CI caught exactly that: the package could not be imported at all without
    the distributed extra installed.
    """
    try:
        from promptsentinel.jobs.redis_queue import RedisJobQueue
        from promptsentinel.secrets.redis_store import RedisSecretStore
    except ImportError as exc:
        raise ConfigurationError(
            "PROMPTSENTINEL_REDIS_URL is set but the distributed backend is not "
            'installed. Run: pip install "promptsentinel[redis]"'
        ) from exc
    return RedisJobQueue(url), RedisSecretStore(url)


def _check_authentication(settings: Settings) -> None:
    """Fail closed at startup rather than serving an open instance.

    Refusing to boot is deliberate. The failure mode of a warning here is an
    unauthenticated scanner running for months on an internal network, and nobody
    reads startup warnings.
    """
    if settings.api_key_hashes or settings.allow_unauthenticated:
        return
    raise ConfigurationError(
        "refusing to start: no API keys configured. Generate one with "
        "`promptsentinel keygen` and set PROMPTSENTINEL_API_KEY_HASHES, or set "
        "PROMPTSENTINEL_ALLOW_UNAUTHENTICATED=true if this instance is not reachable "
        "by anyone else."
    )


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
