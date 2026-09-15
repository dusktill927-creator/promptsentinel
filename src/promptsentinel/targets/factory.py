"""Spec -> live Target.

One place that knows how to instantiate every adapter, so the engine depends on the
abstraction and never on a concrete client.
"""

from __future__ import annotations

from promptsentinel.core.errors import ConfigurationError
from promptsentinel.targets.base import Target
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.openai_compatible import OpenAICompatibleTarget
from promptsentinel.targets.spec import MockTargetSpec, OpenAICompatibleTargetSpec, TargetSpec


def build_target(spec: TargetSpec, *, allow_mock: bool) -> Target:
    """Instantiate the adapter for ``spec``.

    ``allow_mock`` is a required keyword rather than a default: a deployment that
    exposes mock targets lets a caller get a "clean" report without any real system
    ever being tested, which is a reporting-integrity problem, not a convenience.
    """
    match spec:
        case OpenAICompatibleTargetSpec():
            return OpenAICompatibleTarget(spec)
        case MockTargetSpec():
            if not allow_mock:
                raise ConfigurationError("mock targets are disabled in this deployment")
            return MockTarget(spec)
        case _:
            raise ConfigurationError(f"unsupported target kind: {type(spec).__name__}")
