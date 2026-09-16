"""Scan submission and retrieval.

The shape here is the async job contract: submit returns 202 with an ID, the client
polls status or waits for a webhook, and the report is a separate resource. Probing an
LLM app takes minutes; a synchronous endpoint would be a timeout generator.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response, status

from promptsentinel.api.deps import (
    DatabaseDep,
    QueueDep,
    RegistryDep,
    SecretsDep,
    SettingsDep,
)
from promptsentinel.api.schemas import (
    ErrorResponse,
    ScanAccepted,
    ScanReport,
    ScanRequest,
    ScanStatusOut,
)
from promptsentinel.core.authorization import require_authorization
from promptsentinel.core.errors import ConfigurationError
from promptsentinel.core.models import Finding, ProbeResult, ScanStatus
from promptsentinel.db.models import ScanRow
from promptsentinel.db.repository import (
    ScanRepository,
    finding_from_row,
    probe_result_from_row,
)
from promptsentinel.reporting import to_sarif
from promptsentinel.secrets import scan_secret_key
from promptsentinel.targets.factory import build_target
from promptsentinel.targets.spec import MockTargetSpec, serialize_with_secrets

router = APIRouter(prefix="/v1/scans", tags=["scans"])


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a scan",
    responses={
        403: {
            "model": ErrorResponse,
            "description": "Authorization attestation missing or invalid",
        },
        400: {"model": ErrorResponse, "description": "Unknown probe or unsupported target"},
    },
)
async def submit_scan(
    request: ScanRequest,
    database: DatabaseDep,
    queue: QueueDep,
    registry: RegistryDep,
    settings: SettingsDep,
    secrets: SecretsDep,
) -> ScanAccepted:
    """Queue a scan against a target you own.

    Order of operations matters and is deliberate:

    1. **Authorization first.** Before the target spec is validated, before anything
       is written, before any probe is resolved. An unauthorized request must leave no
       trace and cost nothing.
    2. Resolve probes -- an unknown probe ID fails loudly rather than running a
       smaller scan than the caller asked for.
    3. Persist, then enqueue. Never the other way round: a worker that starts before
       the row is committed would race its own scan record.
    """
    # 1. The gate. `require_authorization` raises AuthorizationError, which the
    #    application-wide handler turns into 403.
    authorization = require_authorization(
        confirmed=request.authorization.confirmed,
        attested_by=request.authorization.attested_by,
        statement=request.authorization.statement,
        reference=request.authorization.reference,
    )

    if isinstance(request.target, MockTargetSpec) and not settings.allow_mock_targets:
        raise ConfigurationError("mock targets are disabled in this deployment")

    # 2. Resolve the probe selection now so the caller learns about a typo
    #    immediately instead of finding an empty report later.
    probes = registry.select(probe_ids=request.probes, categories=request.categories)
    if not probes:
        raise ConfigurationError("no probes selected")

    # Constructed and discarded purely to validate the spec while we can still return
    # a 4xx; the worker builds its own instance with the live credentials.
    probe_target = build_target(request.target, allow_mock=settings.allow_mock_targets)
    target_description = probe_target.describe()
    await probe_target.aclose()

    # 3. Persist, commit, then enqueue.
    async with database.session() as session:
        scan = await ScanRepository(session).create_scan(
            target_spec=request.target,
            target_description=target_description,
            authorization=authorization,
            requested_probe_ids=[p.id for p in probes],
            options=request.options,
            webhook_url=str(request.webhook_url) if request.webhook_url else None,
        )
        scan_id = scan.id
        created_at = scan.created_at

    # Credentials go to the secret store, not into the queue message. The queue then
    # carries an identifier that is useless on its own.
    await secrets.put(
        scan_secret_key(scan_id),
        serialize_with_secrets(request.target),
        ttl_s=settings.target_secret_ttl_s,
    )
    try:
        await queue.enqueue(scan_id)
    except Exception:
        # Nothing will consume the credential now; do not leave it waiting out its TTL.
        await secrets.delete(scan_secret_key(scan_id))
        raise

    return ScanAccepted(
        id=scan_id,
        status=ScanStatus.PENDING.value,
        created_at=created_at,
        probes_selected=[p.id for p in probes],
        status_url=f"/v1/scans/{scan_id}",
        report_url=f"/v1/scans/{scan_id}/report",
    )


@router.get("", summary="List recent scans")
async def list_scans(
    database: DatabaseDep,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[ScanStatusOut]:
    async with database.session() as session:
        rows = await ScanRepository(session).list_recent(limit=limit, offset=offset)
        return [ScanStatusOut.from_row(row) for row in rows]


@router.get(
    "/{scan_id}",
    summary="Scan status",
    responses={404: {"model": ErrorResponse}},
)
async def get_scan(scan_id: str, database: DatabaseDep) -> ScanStatusOut:
    """Cheap to poll: status only, no findings."""
    async with database.session() as session:
        scan = await ScanRepository(session).get(scan_id)
        if scan is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"scan {scan_id} not found")
        return ScanStatusOut.from_row(scan)


@router.get(
    "/{scan_id}/report/sarif",
    summary="Scan report as SARIF 2.1.0",
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse, "description": "Scan has not finished"},
    },
)
async def get_sarif_report(
    scan_id: str,
    database: DatabaseDep,
    include_evidence: bool = Query(
        default=False,
        description=(
            "Include prompts and responses. Off by default: SARIF is usually uploaded "
            "to a shared platform and evidence contains your application's output."
        ),
    ),
) -> dict[str, Any]:
    """Findings in SARIF, for GitHub code scanning and similar consumers.

    Findings are rebuilt as domain objects on the way out, which re-runs the confidence
    invariant: a row edited directly in the database to claim proof it does not have
    fails here rather than being exported as confirmed.
    """
    async with database.session() as session:
        scan = await _terminal_scan(ScanRepository(session), scan_id)
        results = _domain_results(scan)
        return to_sarif(
            results,
            target=scan.target_description,
            include_evidence=include_evidence,
        )


@router.get(
    "/{scan_id}/report",
    summary="Scan report",
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse, "description": "Scan has not finished"},
    },
)
async def get_report(scan_id: str, database: DatabaseDep, response: Response) -> ScanReport:
    """Full report. Available only once the scan reaches a terminal state.

    A partial report is worse than no report: a caller that sees "0 confirmed
    findings" on a half-finished scan will read it as a pass. 409 forces the client
    to wait, and ``Retry-After`` tells it how long.
    """
    async with database.session() as session:
        scan = await _terminal_scan(ScanRepository(session), scan_id)
        response.headers["Cache-Control"] = "private, max-age=300"
        return ScanReport.from_row(scan)


async def _terminal_scan(repository: ScanRepository, scan_id: str) -> ScanRow:
    """Load a scan, refusing to report on one that has not finished."""
    scan = await repository.get(scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"scan {scan_id} not found")
    if not ScanStatus(scan.status).is_terminal:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                f"scan {scan_id} is {scan.status}; "
                f"poll /v1/scans/{scan_id} until it reaches a terminal state"
            ),
            headers={"Retry-After": "5"},
        )
    return scan


def _domain_results(scan: ScanRow) -> list[ProbeResult]:
    """Regroup stored rows into the domain shape the reporters consume."""
    by_probe: dict[str, list[Finding]] = {}
    for row in scan.findings:
        by_probe.setdefault(row.probe_id, []).append(finding_from_row(row))
    return [probe_result_from_row(run, by_probe.get(run.probe_id, [])) for run in scan.probe_runs]
