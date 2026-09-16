"""Request pacing.

The bucket is tested with an injected clock and sleep, so the pacing logic is verified
exactly and instantly. A rate limiter tested with real sleeps is either a slow suite or
a flaky one.
"""

from __future__ import annotations

import pytest

from promptsentinel.targets.base import ChatMessage, TargetCapability, ToolDefinition
from promptsentinel.targets.factory import build_target
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.rate_limit import RateLimit, RateLimitedTarget, TokenBucket
from promptsentinel.targets.spec import MockTargetSpec, OpenAICompatibleTargetSpec, RetrievalConfig

ASK = [ChatMessage.user("hello")]


class FakeClock:
    """A clock that only advances when something sleeps."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def bucket(clock: FakeClock, *, rate: float = 2.0, burst: int = 4) -> TokenBucket:
    limit = RateLimit(requests_per_second=rate, burst=burst)
    return TokenBucket(limit, clock=clock, sleep=clock.sleep)


class TestTokenBucket:
    async def test_the_burst_is_free(self):
        c = FakeClock()
        b = bucket(c, burst=4)
        for _ in range(4):
            await b.acquire()
        assert c.sleeps == []

    async def test_pacing_engages_once_the_burst_is_spent(self):
        c = FakeClock()
        b = bucket(c, rate=2.0, burst=2)
        await b.acquire()
        await b.acquire()
        await b.acquire()
        assert c.sleeps == [pytest.approx(0.5)], "one token at 2/s is half a second"

    async def test_sustained_rate_matches_the_configuration(self):
        c = FakeClock()
        b = bucket(c, rate=5.0, burst=1)
        for _ in range(11):
            await b.acquire()
        # One free, ten paced at 1/5s each.
        assert c.now == pytest.approx(2.0)

    async def test_tokens_refill_over_time(self):
        c = FakeClock()
        b = bucket(c, rate=2.0, burst=2)
        await b.acquire()
        await b.acquire()
        c.now += 10.0  # idle
        await b.acquire()
        await b.acquire()
        assert c.sleeps == [], "an idle period should restore the burst"

    async def test_refill_is_capped_at_the_burst(self):
        """A long idle period must not bank unlimited requests."""
        c = FakeClock()
        b = bucket(c, rate=2.0, burst=2)
        c.now += 1000.0
        await b.acquire()
        await b.acquire()
        await b.acquire()
        assert c.sleeps, "the third request should still be paced"

    async def test_a_slow_rate_produces_a_long_wait(self):
        c = FakeClock()
        b = bucket(c, rate=0.5, burst=1)
        await b.acquire()
        await b.acquire()
        assert c.sleeps == [pytest.approx(2.0)]

    def test_the_limit_rejects_nonsense(self):
        with pytest.raises(ValueError):
            RateLimit(requests_per_second=0)
        with pytest.raises(ValueError):
            RateLimit(requests_per_second=1, burst=0)


class TestRateLimitedTarget:
    async def test_every_request_is_paced(self):
        c = FakeClock()
        target = RateLimitedTarget(
            MockTarget(MockTargetSpec()),
            RateLimit(requests_per_second=2.0, burst=1),
            clock=c,
            sleep=c.sleep,
        )
        await target.send(ASK)
        await target.send(ASK)
        assert c.sleeps == [pytest.approx(0.5)]
        assert target.requests_made == 2

    async def test_the_response_is_passed_through_unchanged(self):
        inner = MockTarget(MockTargetSpec(default_response="hello there"))
        target = RateLimitedTarget(inner, RateLimit(requests_per_second=100))
        assert (await target.send(ASK)).content == "hello there"

    async def test_documents_and_tools_are_forwarded(self):
        inner = MockTarget(MockTargetSpec(retrieval=RetrievalConfig()))
        target = RateLimitedTarget(inner, RateLimit(requests_per_second=100))
        from promptsentinel.targets.base import Document

        await target.send(ASK, documents=[Document(id="d", title="t", content="c")])
        assert inner.documents_seen[0][0].id == "d"

    async def test_capabilities_are_delegated(self):
        """A probe must see the wrapped target's capabilities, not the wrapper's."""
        inner = MockTarget(
            MockTargetSpec(
                retrieval=RetrievalConfig(), tools=[ToolDefinition(name="t", description="d")]
            )
        )
        target = RateLimitedTarget(inner, RateLimit(requests_per_second=100))
        assert target.supports(TargetCapability.DOCUMENT_INJECTION)
        assert target.supports(TargetCapability.TOOL_CALLING)

    async def test_declared_tools_are_delegated(self):
        tool = ToolDefinition(name="refund", description="d", restricted=True)
        inner = MockTarget(MockTargetSpec(tools=[tool]))
        target = RateLimitedTarget(inner, RateLimit(requests_per_second=100))
        assert [t.name for t in target.declared_tools] == ["refund"]

    async def test_system_prompt_and_description_are_delegated(self):
        inner = MockTarget(MockTargetSpec(system_prompt="You are ACME."))
        target = RateLimitedTarget(inner, RateLimit(requests_per_second=100))
        assert target.system_prompt == "You are ACME."
        assert target.describe() == inner.describe()

    async def test_close_is_delegated(self):
        closed = False

        class Recording(MockTarget):
            async def aclose(self) -> None:
                nonlocal closed
                closed = True

        target = RateLimitedTarget(Recording(MockTargetSpec()), RateLimit(requests_per_second=100))
        await target.aclose()
        assert closed


class TestFactoryWiring:
    def test_a_limit_wraps_the_adapter(self):
        target = build_target(
            MockTargetSpec(), allow_mock=True, rate_limit=RateLimit(requests_per_second=1)
        )
        assert isinstance(target, RateLimitedTarget)
        assert isinstance(target.inner, MockTarget)

    def test_no_limit_returns_the_bare_adapter(self):
        """The API builds a target purely to validate a spec; it sends nothing."""
        target = build_target(MockTargetSpec(), allow_mock=True)
        assert isinstance(target, MockTarget)

    def test_pacing_survives_capability_gating(self):
        spec = OpenAICompatibleTargetSpec(
            base_url="https://x.test/v1", model="m", retrieval=RetrievalConfig()
        )
        target = build_target(spec, allow_mock=False, rate_limit=RateLimit(requests_per_second=1))
        assert target.supports(TargetCapability.DOCUMENT_INJECTION)
