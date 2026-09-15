"""Probe catalogue.

Exposed so clients discover probes at runtime. Without this, every new probe would
need a documentation update and a client release to be usable.
"""

from __future__ import annotations

from fastapi import APIRouter

from promptsentinel.api.deps import RegistryDep
from promptsentinel.api.schemas import ProbeInfo

router = APIRouter(prefix="/v1/probes", tags=["probes"])


@router.get("", summary="List available probes")
async def list_probes(registry: RegistryDep) -> list[ProbeInfo]:
    return [ProbeInfo.from_probe(p) for p in registry.all()]
