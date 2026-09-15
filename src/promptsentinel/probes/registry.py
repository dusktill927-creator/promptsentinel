"""Probe discovery.

Two registration paths, both of which leave the engine untouched:

* **In-tree** -- any module under ``promptsentinel.probes.builtin`` that decorates a
  class with :func:`register`. :func:`ProbeRegistry.discover` imports the package's
  modules, so dropping in a file is enough.
* **Out-of-tree** -- a third-party distribution advertising the
  ``promptsentinel.probes`` entry-point group. Someone can ship their own probe pack
  for their own stack without forking this repo.

Registration is an explicit decorator rather than ``__init_subclass__`` magic. The
cost is one line per probe; the benefit is that test fixtures and abstract
intermediates can subclass :class:`~promptsentinel.probes.base.Probe` freely without
leaking into the production registry.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import pkgutil
from typing import TypeVar

from promptsentinel.core.errors import ConfigurationError
from promptsentinel.core.models import ProbeCategory
from promptsentinel.probes.base import Probe

ProbeT = TypeVar("ProbeT", bound=type[Probe])

ENTRY_POINT_GROUP = "promptsentinel.probes"
BUILTIN_PACKAGE = "promptsentinel.probes.builtin"


class ProbeRegistry:
    """A collection of probe classes, keyed by ``Probe.id``."""

    def __init__(self) -> None:
        self._probes: dict[str, type[Probe]] = {}
        self._discovered = False

    def register(self, probe_cls: ProbeT) -> ProbeT:
        """Decorator. Validates metadata at import time, not at scan time."""
        for attribute in ("id", "name", "category", "description"):
            if not getattr(probe_cls, attribute, None):
                raise ConfigurationError(
                    f"{probe_cls.__name__} must define a non-empty '{attribute}'"
                )
        existing = self._probes.get(probe_cls.id)
        if existing is not None and existing is not probe_cls:
            raise ConfigurationError(
                f"duplicate probe id {probe_cls.id!r}: {existing.__name__} and {probe_cls.__name__}"
            )
        self._probes[probe_cls.id] = probe_cls
        return probe_cls

    def discover(self) -> None:
        """Import built-in probe modules and third-party entry points. Idempotent."""
        if self._discovered:
            return
        self._discovered = True

        package = importlib.import_module(BUILTIN_PACKAGE)
        for module in pkgutil.iter_modules(package.__path__):
            importlib.import_module(f"{BUILTIN_PACKAGE}.{module.name}")

        for entry_point in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP):
            loaded = entry_point.load()
            if isinstance(loaded, type) and issubclass(loaded, Probe):
                self.register(loaded)

    def get(self, probe_id: str) -> type[Probe]:
        self.discover()
        try:
            return self._probes[probe_id]
        except KeyError as exc:
            raise ConfigurationError(f"unknown probe: {probe_id!r}") from exc

    def all(self) -> list[type[Probe]]:
        self.discover()
        return sorted(self._probes.values(), key=lambda p: p.id)

    def select(
        self,
        *,
        probe_ids: list[str] | None = None,
        categories: list[ProbeCategory] | None = None,
    ) -> list[type[Probe]]:
        """Resolve a scan's probe selection.

        An unknown probe id is a hard error rather than a silent no-op: a user who
        typos a probe name must not receive a clean report for a scan that never ran
        what they asked for.
        """
        if probe_ids:
            return [self.get(pid) for pid in probe_ids]
        candidates = [p for p in self.all() if p.default_enabled]
        if categories:
            wanted = set(categories)
            candidates = [p for p in candidates if p.category in wanted]
            if not candidates:
                raise ConfigurationError("no probes match the requested categories")
        return candidates


REGISTRY = ProbeRegistry()
"""Process-wide registry. Tests build their own :class:`ProbeRegistry` for isolation."""

register = REGISTRY.register
