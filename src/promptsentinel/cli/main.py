"""The ``promptsentinel`` command.

The CLI is a thin front end over the same :class:`~promptsentinel.engine.runner.ScanEngine`
the API uses. It builds a :class:`ScanPlan` and hands it over; it does not reimplement
probe selection, scanning, or -- most importantly -- the authorization gate.

That last point is the reason this module is small on purpose. A second entry point is
exactly where a security control quietly acquires a bypass: someone adds a
``--force`` flag "just for local testing" and the gate is gone for everyone who reads
the help text. Here the engine takes an ``Authorization`` object that cannot be
constructed without a valid attestation, so no flag in this file could create one.

Exit codes are part of the contract, because the useful place to run this is CI:

* ``0`` -- the scan ran and found nothing at or above the failure threshold
* ``1`` -- findings at or above the threshold; the gate fails the build
* ``2`` -- the scan could not run at all (refused, misconfigured, unreachable)

``1`` and ``2`` are deliberately distinct. A pipeline must be able to tell "your
application has a confirmed vulnerability" from "the scanner never ran", because
treating the second as the first trains people to ignore both.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from promptsentinel import __version__
from promptsentinel.cli import render
from promptsentinel.core.authorization import REQUIRED_ATTESTATION, require_authorization
from promptsentinel.core.errors import AuthorizationError, PromptSentinelError
from promptsentinel.core.models import Confidence, ProbeCategory
from promptsentinel.engine.runner import ScanEngine, ScanOutcome, ScanPlan
from promptsentinel.probes.registry import REGISTRY
from promptsentinel.targets.factory import build_target
from promptsentinel.targets.spec import (
    MockTargetSpec,
    OpenAICompatibleTargetSpec,
    TargetSpec,
)

app = typer.Typer(
    name="promptsentinel",
    help="Security testing for LLM applications you own or are authorized to test.",
    no_args_is_help=True,
    add_completion=False,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class FailOn(StrEnum):
    """Which findings should fail the build."""

    CONFIRMED = "confirmed"
    SUSPICIOUS = "suspicious"
    NEVER = "never"


def _err(message: str) -> None:
    typer.secho(message, fg=typer.colors.RED, err=True)


def _load_target(
    target_file: Path | None,
    base_url: str | None,
    model: str | None,
    api_key_env: str | None,
    system_prompt: str | None,
) -> TargetSpec:
    """Build a target spec from a file, or from the flags for the simple case.

    A file is the primary path because a realistic target -- retrieval templates, tool
    declarations with their restricted flags -- does not fit on a command line, and it
    is the same JSON the API accepts, so a spec can move between the two unchanged.
    """
    if target_file is not None:
        try:
            raw = json.loads(target_file.read_text())
        except (OSError, ValueError) as exc:
            raise typer.BadParameter(f"could not read target file: {exc}") from exc
        kind = raw.get("kind", "openai_compatible")
        if kind == "mock":
            return MockTargetSpec.model_validate(raw)
        return OpenAICompatibleTargetSpec.model_validate(raw)

    if not base_url or not model:
        raise typer.BadParameter("supply --target FILE, or both --base-url and --model")

    api_key = None
    if api_key_env:
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise typer.BadParameter(f"environment variable {api_key_env} is empty")
    return OpenAICompatibleTargetSpec(
        base_url=base_url, model=model, api_key=api_key, system_prompt=system_prompt
    )


def _attestation(attest: str | None, no_input: bool) -> str:
    """Obtain the attestation, prompting only when a human is present.

    Prompting keeps the gate meaningful for interactive use without making it a
    rubber stamp: the operator types the sentence. In a pipeline there is nobody to
    type it, so ``--attest`` must be passed explicitly and the run is refused
    otherwise -- never defaulted.
    """
    if attest is not None:
        return attest
    if no_input or not sys.stdin.isatty():
        raise AuthorizationError(
            "refusing to scan: no attestation supplied and no terminal to prompt on. "
            f"Pass --attest {REQUIRED_ATTESTATION!r}"
        )
    typer.echo("\nPromptSentinel attacks the target you point it at.")
    typer.echo("To continue, type the following sentence exactly:\n")
    typer.echo(f"  {REQUIRED_ATTESTATION}\n")
    typed: str = typer.prompt("attestation")
    return typed


@app.command()
def scan(
    target_file: Annotated[
        Path | None, typer.Option("--target", "-t", help="JSON target spec (as the API accepts).")
    ] = None,
    base_url: Annotated[str | None, typer.Option(help="OpenAI-compatible base URL.")] = None,
    model: Annotated[str | None, typer.Option(help="Model or deployment name.")] = None,
    api_key_env: Annotated[
        str | None,
        typer.Option(help="Env var holding the target API key. Never pass the key as a flag."),
    ] = None,
    system_prompt: Annotated[
        str | None, typer.Option(help="Your application's real system prompt.")
    ] = None,
    probe: Annotated[list[str] | None, typer.Option(help="Probe ID; repeatable.")] = None,
    category: Annotated[list[str] | None, typer.Option(help="Category; repeatable.")] = None,
    attested_by: Annotated[str, typer.Option(help="Who takes responsibility for this scan.")] = "",
    attest: Annotated[
        str | None, typer.Option(help=f"Attestation. Must read: {REQUIRED_ATTESTATION!r}")
    ] = None,
    reference: Annotated[str | None, typer.Option(help="Ticket or engagement reference.")] = None,
    fail_on: Annotated[
        FailOn, typer.Option(help="Which findings exit non-zero.")
    ] = FailOn.CONFIRMED,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON instead of text.")] = False,
    no_input: Annotated[bool, typer.Option("--no-input", help="Never prompt; for CI.")] = False,
    allow_mock: Annotated[bool, typer.Option(help="Permit mock targets (demos and tests).")] = True,
    probe_timeout: Annotated[float, typer.Option(help="Seconds per probe.")] = 60.0,
    concurrency: Annotated[int, typer.Option(help="Probes in flight at once.")] = 4,
) -> None:
    """Scan a target you own or are authorized to test."""
    try:
        spec = _load_target(target_file, base_url, model, api_key_env, system_prompt)
        authorization = require_authorization(
            confirmed=True,
            attested_by=attested_by,
            statement=_attestation(attest, no_input),
            reference=reference,
        )
        categories = [ProbeCategory(c) for c in category] if category else None
        probes = REGISTRY.select(probe_ids=probe or None, categories=categories)
        target = build_target(spec, allow_mock=allow_mock)
    except AuthorizationError as exc:
        _err(f"\n{exc}\n")
        raise typer.Exit(EXIT_ERROR) from exc
    except (PromptSentinelError, ValueError) as exc:
        _err(f"error: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    plan = ScanPlan(scan_id=f"cli-{os.getpid()}", authorization=authorization, probes=probes)
    engine = ScanEngine(max_concurrent_probes=concurrency, probe_timeout_s=probe_timeout)

    try:
        outcome = asyncio.run(_run(engine, plan, target))
    except PromptSentinelError as exc:
        _err(f"scan failed: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    description = target.describe()
    if json_output:
        typer.echo(render.render_json(outcome, target=description))
    else:
        typer.echo(render.render_text(outcome, target=description))

    raise typer.Exit(_exit_code(outcome, fail_on))


async def _run(engine: ScanEngine, plan: ScanPlan, target) -> ScanOutcome:  # type: ignore[no-untyped-def]
    try:
        return await engine.run(plan, target)
    finally:
        await target.aclose()


def _exit_code(outcome: ScanOutcome, fail_on: FailOn) -> int:
    """Findings at or above the threshold fail the build.

    Note what is *not* here: an errored probe does not fail the build by itself. It is
    printed prominently instead. Conflating "we could not test this" with "this is
    vulnerable" makes a red build meaningless, and the report already shows both.
    """
    if fail_on is FailOn.NEVER:
        return EXIT_OK
    tiers = {Confidence.CONFIRMED}
    if fail_on is FailOn.SUSPICIOUS:
        tiers.add(Confidence.SUSPICIOUS)
    hit = any(f.confidence in tiers for result in outcome.results for f in result.findings)
    return EXIT_FINDINGS if hit else EXIT_OK


@app.command()
def probes(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List available probes."""
    catalogue = REGISTRY.all()
    if json_output:
        typer.echo(
            json.dumps(
                [
                    {
                        "id": p.id,
                        "name": p.name,
                        "category": p.category.value,
                        "description": p.description,
                        "default_enabled": p.default_enabled,
                        "required_capabilities": sorted(c.value for c in p.required_capabilities),
                    }
                    for p in catalogue
                ],
                indent=2,
            )
        )
        return

    for probe_cls in catalogue:
        default = "" if probe_cls.default_enabled else "  (opt-in)"
        typer.echo(f"{probe_cls.id:42} {probe_cls.category.value}{default}")
        typer.echo(f"  {probe_cls.description}")
    typer.echo(f"\n{len(catalogue)} probes")


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
