"""Target construction, including the deployment switch that disables mocks."""

from __future__ import annotations

import pytest

from promptsentinel.core.errors import ConfigurationError
from promptsentinel.targets.base import TargetCapability
from promptsentinel.targets.factory import build_target
from promptsentinel.targets.mock import MockTarget
from promptsentinel.targets.openai_compatible import OpenAICompatibleTarget
from promptsentinel.targets.spec import MockTargetSpec, OpenAICompatibleTargetSpec


class TestConstruction:
    def test_builds_an_openai_compatible_target(self):
        spec = OpenAICompatibleTargetSpec(base_url="https://x.test/v1", model="m")
        assert isinstance(build_target(spec, allow_mock=False), OpenAICompatibleTarget)

    def test_builds_a_mock_target_when_allowed(self):
        assert isinstance(build_target(MockTargetSpec(), allow_mock=True), MockTarget)


class TestMockGate:
    def test_mock_targets_can_be_disabled(self):
        """A mock target yields a clean report with nothing real ever tested.

        A production deployment must be able to refuse it outright.
        """
        with pytest.raises(ConfigurationError, match="mock targets are disabled"):
            build_target(MockTargetSpec(), allow_mock=False)


class TestUnknownKind:
    def test_an_unhandled_spec_type_is_rejected(self):
        """Adding a spec without an adapter must fail loudly, not fall through."""

        class FutureSpec:
            kind = "quantum"

        with pytest.raises(ConfigurationError, match="unsupported target kind"):
            build_target(FutureSpec(), allow_mock=True)  # type: ignore[arg-type]


class TestCapabilities:
    def test_openai_target_advertises_the_capabilities_probes_need(self):
        spec = OpenAICompatibleTargetSpec(base_url="https://x.test/v1", model="m")
        target = build_target(spec, allow_mock=False)
        assert target.supports(TargetCapability.SYSTEM_PROMPT_CONTROL)
        assert target.supports(TargetCapability.TOOL_CALLING)

    def test_system_prompt_is_exposed_to_probes(self):
        spec = OpenAICompatibleTargetSpec(
            base_url="https://x.test/v1", model="m", system_prompt="You are ACME support."
        )
        assert build_target(spec, allow_mock=False).system_prompt == "You are ACME support."

    def test_base_target_exposes_no_system_prompt_by_default(self):
        spec = MockTargetSpec()
        assert build_target(spec, allow_mock=True).system_prompt is None
