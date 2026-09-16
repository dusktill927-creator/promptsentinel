"""Spec -> live Target.

One place that knows how to instantiate every adapter, so the engine depends on the
abstraction and never on a concrete client.
"""

from __future__ import annotations

from promptsentinel.core.errors import ConfigurationError
from promptsentinel.targets.base import Target
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.openai_compatible import OpenAICompatibleTarget
from promptsentinel.targets.rate_limit import RateLimit, RateLimitedTarget
from promptsentinel.targets.spec import MockTargetSpec, OpenAICompatibleTargetSpec, TargetSpec


def build_target(
    spec: TargetSpec, *, allow_mock: bool, rate_limit: RateLimit | None = None
) -> Target:
    """Instantiate the adapter for ``spec``, paced if a limit is given.

    ``allow_mock`` is a required keyword rather than a default: a deployment that
    exposes mock targets lets a caller get a "clean" report without any real system
    ever being tested, which is a reporting-integrity problem, not a convenience.

    ``rate_limit`` is applied here so every caller that actually scans gets pacing from
    one place. It is optional because the API layer also builds a target purely to
    validate a spec and read its description, which sends nothing.
    """
    target = _adapter(spec, allow_mock=allow_mock)
    return RateLimitedTarget(target, rate_limit) if rate_limit else target


def _adapter(spec: TargetSpec, *, allow_mock: bool) -> Target:
    match spec:
        case OpenAICompatibleTargetSpec():
            return OpenAICompatibleTarget(spec)
        case MockTargetSpec():
            if not allow_mock:
                raise ConfigurationError("mock targets are disabled in this deployment")
            return MockTarget(spec)
        case _:
            raise ConfigurationError(f"unsupported target kind: {type(spec).__name__}")
