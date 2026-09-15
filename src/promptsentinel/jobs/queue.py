"""Job queue abstraction.

V1 ships an in-process queue: scans run as asyncio tasks inside the API process. That
is honest about what it is -- good enough for one operator scanning their own apps,
and it loses queued work on restart.

The point of the :class:`JobQueue` protocol is that replacing it with Redis/ARQ or
Celery later is a new class and one line of wiring, not a rewrite of the API layer.
The API already talks to an interface, and already returns 202 with a job ID rather
than blocking -- which is the part that would be expensive to retrofit.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Protocol

from promptsentinel.targets.spec import TargetSpec

logger = logging.getLogger(__name__)

ScanRunner = Callable[[str, TargetSpec], Awaitable[None]]


class JobQueue(Protocol):
    """Anything that can run a scan out of band."""

    async def enqueue(self, scan_id: str, target_spec: TargetSpec) -> None:
        """Schedule a scan. Must return promptly; must not run the scan inline."""
        ...

    async def aclose(self) -> None:
        """Wait for in-flight work and release resources."""
        ...


class InProcessJobQueue:
    """Runs scans as asyncio tasks in the API process.

    ``target_spec`` is passed through memory rather than re-read from the database on
    purpose: the persisted copy has its credentials redacted, so there is no path by
    which an API key is written to disk. A distributed queue would need a secrets
    backend here -- a deliberate trade recorded in docs/ARCHITECTURE.md.
    """

    def __init__(self, runner: ScanRunner, *, max_concurrent: int = 2):
        self._runner = runner
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tasks: set[asyncio.Task[None]] = set()

    async def enqueue(self, scan_id: str, target_spec: TargetSpec) -> None:
        task = asyncio.create_task(self._execute(scan_id, target_spec), name=f"scan:{scan_id}")
        # Hold a strong reference: asyncio only keeps weak ones, and an unreferenced
        # task can be garbage collected mid-run.
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _execute(self, scan_id: str, target_spec: TargetSpec) -> None:
        async with self._semaphore:
            try:
                await self._runner(scan_id, target_spec)
            except Exception:
                # The worker already records failures against the scan row. Anything
                # reaching here would otherwise become a silently swallowed task
                # exception, so it is logged loudly.
                logger.exception("scan=%s job crashed outside the worker", scan_id)

    async def wait_idle(self) -> None:
        """Block until every scheduled scan has finished. Used by tests and shutdown."""
        while self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)

    async def aclose(self) -> None:
        await self.wait_idle()
