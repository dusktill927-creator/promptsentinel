"""A thin, read-only dashboard.

Deliberately thin. The API and the CLI are the product surface; this exists so someone
can look at scans without curl, and it has **no capability they lack**. Every route is a
GET that renders data the API already serves, with one exception -- the login POST that
exchanges an API key for a cookie.

Read-only is also the security posture. There are no state-changing endpoints, so there
is no CSRF surface worth the name, and nothing here can start a scan. Starting a scan
requires typing an attestation, and a web form is exactly the place where people click
through an attestation without reading it.

Disabled unless ``PROMPTSENTINEL_ENABLE_DASHBOARD`` is set.
"""

from __future__ import annotations

from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from promptsentinel.api.deps import DatabaseDep, SettingsDep
from promptsentinel.api.routes.scans import _domain_results
from promptsentinel.api.security import verify
from promptsentinel.core.models import Confidence, ScanStatus
from promptsentinel.db.models import ScanRow
from promptsentinel.db.repository import ScanRepository
from promptsentinel.reporting.html import esc, page, render_report

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

COOKIE_NAME = "promptsentinel_session"
MAX_LOGIN_BODY = 4096
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def _html(body: str, title: str, *, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(page(title, body), status_code=status_code, headers=SECURITY_HEADERS)


def _authenticate(request: Request) -> None:
    """Accept the API key from the session cookie or the usual header.

    The cookie *is* the API key rather than a session token backed by a store. For a
    read-only, self-hosted dashboard that is the honest trade: inventing session
    management would add more security-relevant code than it removes. HttpOnly keeps it
    away from scripts, SameSite=strict keeps it off cross-site requests, and it is
    scoped to this path so it is never sent to the API routes.
    """
    settings = request.app.state.settings
    if settings.allow_unauthenticated:
        return
    presented = request.cookies.get(COOKIE_NAME) or request.headers.get("x-api-key")
    if presented and verify(presented, settings.api_key_hashes):
        return
    raise HTTPException(
        status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/dashboard/login"}
    )


def _login_page(*, error: str | None = None) -> str:
    message = f'<p class="caveat">{esc(error)}</p>' if error else ""
    return (
        '<main style="max-width:26rem">'
        "<h1>PromptSentinel</h1>"
        '<p class="sub">Enter an API key to view scans.</p>'
        f"{message}"
        '<form method="post" action="/dashboard/login">'
        '<p><input type="password" name="key" autocomplete="off" '
        'style="width:100%;padding:.6rem;font:inherit" placeholder="ps_..." autofocus></p>'
        '<p><button type="submit" style="padding:.6rem 1rem;font:inherit">Sign in</button></p>'
        "</form></main>"
    )


@router.get("/login", summary="Dashboard sign-in", include_in_schema=False)
async def login_form() -> HTMLResponse:
    return _html(_login_page(), "Sign in - PromptSentinel")


@router.post(
    "/login",
    summary="Exchange an API key for a session",
    include_in_schema=False,
    # The handler returns a page on failure and a redirect on success; FastAPI cannot
    # build a response model from that union, and there is nothing to document anyway.
    response_model=None,
)
async def login(request: Request, settings: SettingsDep) -> HTMLResponse | RedirectResponse:
    """Parse the form with the standard library.

    Starlette's form parsing needs ``python-multipart`` even for urlencoded bodies, and
    one field on one form does not justify another dependency in a security tool. The
    body is size-capped first so an unauthenticated caller cannot make the process read
    an arbitrary amount into memory.
    """
    if int(request.headers.get("content-length") or 0) > MAX_LOGIN_BODY:
        # Literal rather than the starlette constant, which has been renamed across
        # versions; this project supports a range of them.
        raise HTTPException(413, "login body too large")
    raw = (await request.body())[:MAX_LOGIN_BODY].decode("utf-8", errors="replace")
    key = (parse_qs(raw).get("key") or [""])[0]

    if not key or not verify(key, settings.api_key_hashes):
        # Same wording whatever went wrong, matching the API's 401.
        return _html(
            _login_page(error="That key was not accepted."),
            "Sign in - PromptSentinel",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    response = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        COOKIE_NAME,
        key,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/dashboard",
        max_age=8 * 60 * 60,
    )
    return response


@router.get("", summary="Recent scans", include_in_schema=False)
async def index(request: Request, database: DatabaseDep) -> HTMLResponse:
    _authenticate(request)
    async with database.session() as session:
        scans = await ScanRepository(session).list_recent(limit=50)
        rows = "".join(_scan_row(scan) for scan in scans)

    body = (
        "<main><h1>Scans</h1>"
        '<p class="sub">The 50 most recent scans. Submit new ones through the API or CLI.</p>'
        + (
            "<table><thead><tr><th>Scan</th><th>Target</th><th>Status</th>"
            "<th>Confirmed</th><th>Started</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            if rows
            else "<p>No scans yet.</p>"
        )
        + "</main>"
    )
    return _html(body, "Scans - PromptSentinel")


def _scan_row(scan: ScanRow) -> str:
    """One table row. Everything interpolated goes through esc()."""
    confirmed = sum(1 for f in scan.findings if f.confidence == Confidence.CONFIRMED.value)
    label = esc(scan.id[:12])
    link = (
        f'<a href="/dashboard/scans/{esc(scan.id)}">{label}</a>'
        if ScanStatus(scan.status).is_terminal
        else label
    )
    return (
        f"<tr><td>{link}</td><td>{esc(scan.target_description)}</td>"
        f"<td>{esc(scan.status)}</td><td>{confirmed}</td>"
        f"<td>{esc(scan.created_at.strftime('%Y-%m-%d %H:%M'))}</td></tr>"
    )


@router.get("/scans/{scan_id}", summary="Scan report", include_in_schema=False)
async def report(request: Request, scan_id: str, database: DatabaseDep) -> HTMLResponse:
    _authenticate(request)
    async with database.session() as session:
        scan = await ScanRepository(session).get(scan_id)
        if scan is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="scan not found")
        if not ScanStatus(scan.status).is_terminal:
            raise HTTPException(status.HTTP_409_CONFLICT, detail="scan has not finished")
        document = render_report(
            _domain_results(scan),
            target=scan.target_description,
            scan_id=scan.id,
            generated_at=scan.finished_at,
            seeded=[dict(entry) for entry in scan.canaries_seeded],
        )
    return HTMLResponse(document, headers=SECURITY_HEADERS)
