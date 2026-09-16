"""Request pacing for the system under test.

``max_concurrent_probes`` bounds how many probes run at once. It does not bound the
*rate*: four probes against a fast endpoint can still produce hundreds of requests a
second, and the target is the operator's production application. A security scan that
degrades the thing it is testing is an outage the operator caused by trying to be
careful, which is the worst way to learn this lesson.

Pacing is applied by composition -- :class:`RateLimitedTarget` wraps any
:class:`~promptsentinel.targets.base.Target` -- rather than inside each adapter. Every
target kind is therefore paced by construction, including ones added later, and no new
adapter can forget to do it.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from promptsentinel.core.budget import extend_deadline
from promptsentinel.targets.base import (
    ChatMessage,
    DelegatingTarget,
    Document,
    Target,
    TargetResponse,
    ToolSpec,
)


class RateLimit(BaseModel):
    """How hard a target may be hit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    requests_per_second: float = Field(gt=0, le=1000)
    burst: int = Field(default=4, ge=1, le=1000)
    """Requests allowed back to back before pacing engages.

    A small burst keeps short scans fast without letting a long one sustain a load the
    application was never sized for."""


class TokenBucket:
    """Paces requests by assigning each caller a send slot.

    Rather than holding tokens and sleeping until one appears, each caller takes the
    next free slot on a schedule and waits for it. Two things fall out of that, both of
    which the sleep-on-a-token version got wrong:

    * **The wait is known before it starts.** That lets a caller credit the wait to its
      deadline *up front*. Crediting afterwards is useless -- an ``asyncio.timeout``
      fires during the sleep, before the credit is ever applied, which is exactly the
      bug this replaced.
    * **The lock is never held across a wait.** Callers take a slot in a fast critical
      section and then sleep independently, so nobody queues behind anyone else's sleep
      and there is no thundering herd, because every caller has a different slot.

    ``clock`` and ``sleep`` are injectable so the pacing is tested exactly, at no
    wall-clock cost. A rate limiter verified with real sleeps is either a slow test
    suite or a flaky one.
    """

    def __init__(
        self,
        limit: RateLimit,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ):
        self._interval = 1.0 / limit.requests_per_second
        self._burst = limit.burst
        self._clock = clock
        self._sleep = sleep or asyncio.sleep
        self._lock = asyncio.Lock()
        # Start far enough in the past that the first `burst` callers go straight
        # through, and an idle period restores the same allowance.
        self._next_free = clock() - self._burst * self._interval

    async def acquire(self) -> None:
        """Wait until this caller may send."""
        async with self._lock:
            now = self._clock()
            # Let the schedule lag behind now by at most one burst, so idling banks the
            # burst allowance again but never more than that.
            floor = now - (self._burst - 1) * self._interval
            slot = max(now, self._next_free)  # floor is never above now
            self._next_free = max(self._next_free, floor) + self._interval
            wait = slot - now

        if wait > 0:
            # Credited before the wait, not after: the caller is about to be blocked by
            # us rather than by the target, and a deadline that expires mid-sleep never
            # gets to hear about a credit applied afterwards.
            extend_deadline(wait)
            await self._sleep(wait)


class RateLimitedTarget(DelegatingTarget):
    """Paces every request to the wrapped target."""

    kind: ClassVar[str] = "rate_limited"

    def __init__(self, inner: Target, limit: RateLimit, **bucket_kwargs: object):
        super().__init__(inner)
        self._bucket = TokenBucket(limit, **bucket_kwargs)  # type: ignore[arg-type]
        self.requests_made = 0

    async def send(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[ToolSpec] | None = None,
        documents: Sequence[Document] | None = None,
    ) -> TargetResponse:
        await self._bucket.acquire()
        self.requests_made += 1
        return await super().send(messages, tools=tools, documents=documents)
