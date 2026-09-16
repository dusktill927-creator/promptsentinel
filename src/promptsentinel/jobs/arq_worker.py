"""Worker process entry point.

Run with ``promptsentinel worker``.

That is the only supported entry point, deliberately. arq's own
``arq module.WorkerSettings`` form reads its Redis connection from the settings class
alone, and would quietly fall back to ``localhost:6379`` when this project's
``PROMPTSENTINEL_REDIS_URL`` is set to something else -- a worker connected to the
wrong broker, sitting there processing nothing, with no error anywhere. The CLI builds
the connection from the same :class:`Settings` the API uses and passes it in
explicitly.

The worker owns its own database engine and secret-store connection. It shares no
state with the API beyond Redis and the database, which is what lets it run on another
machine, and several of them run at once.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any, ClassVar

from arq.connections import RedisSettings

from promptsentinel.config import Settings, get_settings
from promptsentinel.db.session import Database
from promptsentinel.jobs.worker import ScanWorker
from promptsentinel.probes.registry import REGISTRY
from promptsentinel.secrets.redis_store import RedisSecretStore

logger = logging.getLogger(__name__)


async def run_scan(ctx: dict[str, Any], scan_id: str) -> None:
    """Execute one scan.

    Failures are recorded against the scan row by :class:`ScanWorker` rather than
    raised, so arq does not retry a scan that failed for a reason retrying cannot fix
    -- an unknown probe, a revoked attestation, a target that refuses to answer.
    """
    worker: ScanWorker = ctx["scan_worker"]
    await worker.execute(scan_id)


async def startup(ctx: dict[str, Any]) -> None:
    settings = get_settings()
    if not settings.redis_url:
        raise RuntimeError("PROMPTSENTINEL_REDIS_URL must be set to run a worker")

    database = Database(settings.database_url)
    secrets = RedisSecretStore(settings.redis_url)
    REGISTRY.discover()

    ctx["database"] = database
    ctx["secrets"] = secrets
    ctx["scan_worker"] = ScanWorker(database, settings, secrets, registry=REGISTRY)
    logger.info("promptsentinel worker ready with %d probes", len(REGISTRY.all()))


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["secrets"].aclose()
    await ctx["database"].dispose()


def _redis_settings(settings: Settings | None = None) -> RedisSettings:
    resolved = settings or get_settings()
    if not resolved.redis_url:
        raise RuntimeError("PROMPTSENTINEL_REDIS_URL must be set to run a worker")
    return RedisSettings.from_dsn(resolved.redis_url)


class WorkerSettings:
    """arq worker configuration.

    A plain class rather than a subclass of arq's ``WorkerSettingsBase`` protocol: arq
    reads these off ``__dict__``, and inheriting the protocol makes mypy treat the
    lifecycle hooks as methods that would be handed a ``self`` arq never passes.
    """

    functions: ClassVar[Sequence[Any]] = (run_scan,)
    on_startup = startup
    on_shutdown = shutdown
    # One scan at a time per worker process by default: a scan is mostly waiting on a
    # rate-limited target, and running more of them concurrently multiplies the load on
    # someone's production application rather than getting through the queue faster.
    max_jobs = 1
    job_timeout = 3600
    keep_result = 0
