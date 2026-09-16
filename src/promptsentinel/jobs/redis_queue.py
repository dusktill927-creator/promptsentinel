"""Redis-backed job queue, via arq.

This is the implementation the :class:`~promptsentinel.jobs.queue.JobQueue` protocol
was written for. Everything above it -- the API returning 202, the polling contract,
the webhooks -- is unchanged, which was the point of defining the protocol before there
was a second implementation.

arq rather than a hand-rolled Redis list: retries, job expiry, health checks and
graceful shutdown are the parts that take real effort to get right, and they are not
where this project's value lies.
"""

from __future__ import annotations

import logging

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

logger = logging.getLogger(__name__)

RUN_SCAN = "run_scan"
"""Name of the task the worker registers. Shared constant, not a string typed twice."""


class RedisJobQueue:
    """Publishes scan IDs to Redis for a separate worker process to pick up."""

    def __init__(self, url: str, *, pool: ArqRedis | None = None):
        self._url = url
        self._pool = pool

    async def _connect(self) -> ArqRedis:
        if self._pool is None:
            self._pool = await create_pool(RedisSettings.from_dsn(self._url))
        return self._pool

    async def enqueue(self, scan_id: str) -> None:
        """Publish the scan ID.

        The job ID is the scan ID, which makes enqueuing idempotent: a retried submission
        cannot produce two workers scanning one target twice.
        """
        pool = await self._connect()
        job = await pool.enqueue_job(RUN_SCAN, scan_id, _job_id=f"scan:{scan_id}")
        if job is None:
            logger.warning("scan=%s was already queued; not enqueued twice", scan_id)

    async def aclose(self) -> None:
        if self._pool is not None:
            await self._pool.aclose()
            self._pool = None
