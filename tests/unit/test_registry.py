"""Probe discovery and selection."""

from __future__ import annotations

import pytest

from promptsentinel.core.errors import ConfigurationError
from promptsentinel.core.models import ProbeCategory, ProbeResult
from promptsentinel.probes.base import Probe, ProbeContext
from promptsentinel.probes.registry import REGISTRY, ProbeRegistry
from promptsentinel.targets.base import Target


def make_probe(probe_id="x.y", category=ProbeCategory.DIAGNOSTIC, enabled=True, **extra):
    attrs = {
        "id": probe_id,
        "name": "N",
        "category": category,
        "description": "D",
        "default_enabled": enabled,
        "run": _noop_run,
        **extra,
    }
    return type("Generated", (Probe,), attrs)


async def _noop_run(self, target: Target, context: ProbeContext) -> ProbeResult:
    return ProbeResult.completed(self.id, [])


class TestRegistration:
    def test_register_returns_the_class(self):
        registry = ProbeRegistry()
        probe = make_probe()
        assert registry.register(probe) is probe

    @pytest.mark.parametrize("missing", ["id", "name", "category", "description"])
    def test_missing_metadata_fails_at_registration(self, missing):
        """Caught at import time, not halfway through a user's scan."""
        registry = ProbeRegistry()
        probe = make_probe(**{missing: ""})
        with pytest.raises(ConfigurationError, match=missing):
            registry.register(probe)

    def test_duplicate_ids_are_rejected(self):
        """Two probes sharing an ID would make one of them silently unreachable."""
        registry = ProbeRegistry()
        registry.register(make_probe("dup"))
        with pytest.raises(ConfigurationError, match="duplicate probe id"):
            registry.register(make_probe("dup"))

    def test_re_registering_the_same_class_is_idempotent(self):
        registry = ProbeRegistry()
        probe = make_probe("same")
        registry.register(probe)
        registry.register(probe)

    def test_subclassing_probe_does_not_auto_register(self):
        """Explicit registration keeps test doubles out of the production registry."""
        make_probe("tests.never_registered")
        assert "tests.never_registered" not in [p.id for p in REGISTRY.all()]


class TestDiscovery:
    def test_builtin_probes_are_found(self):
        assert "diagnostic.canary_echo" in [p.id for p in REGISTRY.all()]

    def test_discovery_is_idempotent(self):
        REGISTRY.discover()
        before = len(REGISTRY.all())
        REGISTRY.discover()
        assert len(REGISTRY.all()) == before


class TestSelection:
    def test_unknown_probe_id_is_a_hard_error(self):
        """A typo must not silently produce a clean report for a scan that never ran."""
        with pytest.raises(ConfigurationError, match="unknown probe"):
            REGISTRY.select(probe_ids=["nope.nope"])

    def test_explicit_ids_are_honoured(self):
        selected = REGISTRY.select(probe_ids=["diagnostic.canary_echo"])
        assert [p.id for p in selected] == ["diagnostic.canary_echo"]

    def test_category_filter(self):
        registry = ProbeRegistry()
        registry._discovered = True  # skip entry-point scan; this registry is synthetic
        registry.register(make_probe("a.jail", ProbeCategory.JAILBREAK))
        registry.register(make_probe("b.diag", ProbeCategory.DIAGNOSTIC))
        selected = registry.select(categories=[ProbeCategory.JAILBREAK])
        assert [p.id for p in selected] == ["a.jail"]

    def test_empty_category_match_is_an_error(self):
        registry = ProbeRegistry()
        registry._discovered = True
        registry.register(make_probe("a.diag", ProbeCategory.DIAGNOSTIC))
        with pytest.raises(ConfigurationError, match="no probes match"):
            registry.select(categories=[ProbeCategory.JAILBREAK])

    def test_default_excludes_opt_in_probes(self):
        registry = ProbeRegistry()
        registry._discovered = True
        registry.register(make_probe("a.on", enabled=True))
        registry.register(make_probe("b.off", enabled=False))
        assert [p.id for p in registry.select()] == ["a.on"]
