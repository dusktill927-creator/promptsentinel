"""Job queue abstraction.

Two implementations share one contract: an in-process queue for a single-process
deployment, and a Redis-backed one for anything else.

A queue message is **just a scan ID**. Everything else the worker needs is in the
database, and the one thing that cannot be -- the target's credentials -- travels
through :mod:`promptsentinel.secrets` instead. Putting a credential in a queue payload
would spread it across every broker, replica and backup that message touches, and queue
payloads are exactly what people dump when debugging.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Protocol

logger = logging.getLogger(__name__)

ScanRunner = Callable[[str], Awaitable[None]]


class JobQueue(Protocol):
    """Anything that can run a scan out of band."""

    async def enqueue(self, scan_id: str) -> None:
        """Schedule a scan. Must return promptly; must not run the scan inline."""
        ...

    async def aclose(self) -> None:
        """Wait for in-flight work and release resources."""
        ...


class InProcessJobQueue:
    """Runs scans as asyncio tasks in the API process.

    Simple and honest about its limits: queued scans are lost on restart, and it only
    scales as far as one process. It takes the same scan-ID-only contract as the
    distributed queue, so nothing above it knows which one is in use.
    """

    def __init__(self, runner: ScanRunner, *, max_concurrent: int = 2):
        self._runner = runner
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tasks: set[asyncio.Task[None]] = set()

    async def enqueue(self, scan_id: str) -> None:
        task = asyncio.create_task(self._execute(scan_id), name=f"scan:{scan_id}")
        # Hold a strong reference: asyncio only keeps weak ones, and an unreferenced
        # task can be garbage collected mid-run.
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _execute(self, scan_id: str) -> None:
        async with self._semaphore:
            try:
                await self._runner(scan_id)
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
