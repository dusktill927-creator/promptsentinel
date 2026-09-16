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

from promptsentinel.targets.base import (
    ChatMessage,
    Document,
    Target,
    TargetCapability,
    TargetResponse,
    ToolDefinition,
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
    """Async token bucket.

    ``clock`` and ``sleep`` are injectable so the pacing logic can be tested exactly,
    at no wall-clock cost. A rate limiter verified with real sleeps is either a slow
    test suite or a flaky one.
    """

    def __init__(
        self,
        limit: RateLimit,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ):
        self._rate = limit.requests_per_second
        self._burst = float(limit.burst)
        self._tokens = float(limit.burst)
        self._clock = clock
        self._sleep = sleep or asyncio.sleep
        self._updated = clock()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until one request may be sent.

        The lock is deliberately held across the wait. Releasing it first would let
        every queued caller wake at once and fire together -- the exact burst this
        exists to prevent -- so waiters are served one at a time, in order.
        """
        async with self._lock:
            self._refill()
            if self._tokens < 1.0:
                await self._sleep((1.0 - self._tokens) / self._rate)
                self._refill()
            self._tokens = max(0.0, self._tokens - 1.0)

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)


class RateLimitedTarget(Target):
    """Paces every request to the wrapped target.

    Delegation is written out rather than done with ``__getattr__`` so that a new
    member of the :class:`Target` interface fails type checking here instead of
    silently bypassing the limiter at runtime.
    """

    kind: ClassVar[str] = "rate_limited"

    def __init__(self, inner: Target, limit: RateLimit, **bucket_kwargs: object):
        self._inner = inner
        self._bucket = TokenBucket(limit, **bucket_kwargs)  # type: ignore[arg-type]
        self.requests_made = 0

    @property
    def inner(self) -> Target:
        return self._inner

    @property
    def capabilities(self) -> frozenset[TargetCapability]:
        return self._inner.capabilities

    @property
    def declared_tools(self) -> Sequence[ToolDefinition]:
        return self._inner.declared_tools

    @property
    def system_prompt(self) -> str | None:
        return self._inner.system_prompt

    def describe(self) -> str:
        return self._inner.describe()

    async def send(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[ToolSpec] | None = None,
        documents: Sequence[Document] | None = None,
    ) -> TargetResponse:
        await self._bucket.acquire()
        self.requests_made += 1
        return await self._inner.send(messages, tools=tools, documents=documents)

    async def aclose(self) -> None:
        await self._inner.aclose()
