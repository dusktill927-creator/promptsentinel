"""The per-probe time budget.

A probe has a deadline so a hung target cannot stall a scan forever. That deadline is
supposed to measure *the target's* responsiveness -- but a probe also spends time
waiting on PromptSentinel's own rate limiter, and a scan paced for a free-tier API can
easily spend more time queued than talking.

Left alone, that produces the worst kind of wrong answer: probes reported ``TIMED_OUT``
when nothing timed out, blaming the target for our own queueing. Measured against a
2 requests/second limit the default configuration was fine; at 0.2/s, three probes in
four were reported as failures they had not suffered.

So the limiter extends the deadline by exactly as long as it made the probe wait. The
budget then means what it claims to: time the target had, not time it spent in our
queue. A context variable carries the active deadline, which keeps the rate limiter
from having to know anything about the engine -- this module sits below both.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_ACTIVE: ContextVar[asyncio.Timeout | None] = ContextVar("promptsentinel_deadline", default=None)


@contextmanager
def track_deadline(timeout: asyncio.Timeout) -> Iterator[None]:
    """Publish ``timeout`` as the deadline for work in this task."""
    token = _ACTIVE.set(timeout)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def extend_deadline(seconds: float) -> None:
    """Give back time spent waiting on us rather than on the target.

    A no-op when nothing is tracking a deadline, so the rate limiter behaves the same
    whether it is driven by the engine, the CLI, or a test.
    """
    if seconds <= 0:
        return
    timeout = _ACTIVE.get()
    if timeout is None:
        return
    when = timeout.when()
    if when is not None:
        timeout.reschedule(when + seconds)
