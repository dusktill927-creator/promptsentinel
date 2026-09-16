"""Standalone HTML reports.

A scan report is something people send to each other: to the team that owns the
application, to a reviewer, into a ticket. JSON is not that, and SARIF is a machine
format. This produces one self-contained file that opens anywhere.

**No build step, no framework, no external resources.** The CSS is inline and there is
no JavaScript -- collapsible sections use ``<details>``. That keeps the file readable
offline and with no network, and it keeps an npm dependency tree out of a security
tool, where it would be a supply-chain surface pointed straight at the people least
able to afford one.

**Everything interpolated is escaped.** A report is built almost entirely from text the
*target* produced, and a target under test is, by construction, something an attacker
may control. A scanner that renders its own findings unescaped hands whoever owns that
endpoint script execution in the browser of the person reading the report. Every value
goes through :func:`esc`; there is no other way to put a value into the output.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from datetime import datetime

from promptsentinel import __version__
from promptsentinel.core.models import (
    Confidence,
    Finding,
    ProbeResult,
    ProbeStatus,
    Severity,
    utcnow,
)

_CONFIDENCE_ORDER = {
    Confidence.CONFIRMED: 0,
    Confidence.SUSPICIOUS: 1,
    Confidence.INFORMATIONAL: 2,
}
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

STYLES = """
:root { color-scheme: light dark; --fg:#1a1a1a; --muted:#666; --bg:#fff;
  --card:#f7f7f8; --line:#e2e2e5; --confirmed:#b3261e; --suspicious:#a06800;
  --informational:#1b5e9c; --ok:#1e7a3c; }
@media (prefers-color-scheme: dark) { :root { --fg:#e8e8ea; --muted:#9a9aa0;
  --bg:#141416; --card:#1d1d20; --line:#2e2e33; --confirmed:#ff6b5e;
  --suspicious:#e0a030; --informational:#6bb0ff; --ok:#4cc46e; } }
* { box-sizing: border-box; }
body { margin:0; padding:2rem 1.25rem 4rem; background:var(--bg); color:var(--fg);
  font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size:1.6rem; margin:0 0 .25rem; }
h2 { font-size:1.1rem; margin:2.5rem 0 .75rem; }
.sub { color:var(--muted); margin:0 0 1.5rem; font-size:.9rem; }
.tiles { display:flex; flex-wrap:wrap; gap:.75rem; margin:1.5rem 0; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:8px;
  padding:.75rem 1rem; min-width:7.5rem; }
.tile .n { font-size:1.5rem; font-weight:600; display:block; }
.tile .l { color:var(--muted); font-size:.8rem; text-transform:uppercase;
  letter-spacing:.04em; }
.n.confirmed{color:var(--confirmed)} .n.suspicious{color:var(--suspicious)}
.n.informational{color:var(--informational)} .n.ok{color:var(--ok)}
.finding { background:var(--card); border:1px solid var(--line);
  border-left:4px solid var(--line); border-radius:8px; padding:1rem 1.25rem;
  margin-bottom:1rem; }
.finding.confirmed{border-left-color:var(--confirmed)}
.finding.suspicious{border-left-color:var(--suspicious)}
.finding.informational{border-left-color:var(--informational)}
.badges { display:flex; gap:.5rem; flex-wrap:wrap; margin-bottom:.5rem; }
.badge { font-size:.72rem; text-transform:uppercase; letter-spacing:.05em;
  font-weight:600; padding:.15rem .5rem; border-radius:999px;
  border:1px solid currentColor; }
.badge.confirmed{color:var(--confirmed)} .badge.suspicious{color:var(--suspicious)}
.badge.informational{color:var(--informational)} .badge.plain{color:var(--muted)}
.finding h3 { margin:.1rem 0 .5rem; font-size:1.02rem; }
.finding p { margin:.5rem 0; }
.proof { background:var(--bg); border:1px solid var(--line); border-radius:6px;
  padding:.6rem .8rem; font-size:.88rem; margin:.75rem 0; }
.caveat { color:var(--suspicious); font-size:.88rem; }
details { margin-top:.75rem; } summary { cursor:pointer; color:var(--muted);
  font-size:.88rem; }
pre { background:var(--bg); border:1px solid var(--line); border-radius:6px;
  padding:.75rem; overflow-x:auto; font-size:.82rem; white-space:pre-wrap;
  word-break:break-word; margin:.5rem 0 0; }
table { border-collapse:collapse; width:100%; font-size:.9rem; }
th,td { text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:600; font-size:.8rem; text-transform:uppercase;
  letter-spacing:.04em; }
.status-skipped{color:var(--muted)} .status-errored,.status-timed_out{color:var(--confirmed)}
.notice { border:1px solid var(--line); border-left:4px solid var(--suspicious);
  background:var(--card); border-radius:8px; padding:.75rem 1rem; font-size:.88rem;
  margin:1.5rem 0; }
footer { color:var(--muted); font-size:.82rem; margin-top:3rem;
  border-top:1px solid var(--line); padding-top:1rem; }
a { color:inherit; }
"""


def page(title: str, body: str) -> str:
    """Wrap page content in the shared document shell.

    Exported so the dashboard renders in the same style without duplicating it, and
    -- more to the point -- without a second place where markup is assembled and
    escaping could be forgotten.
    """
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{esc(title)}</title>"
        f"<style>{STYLES}</style></head><body>{body}</body></html>"
    )


def esc(value: object) -> str:
    """Escape a value for HTML. The only way anything reaches the output."""
    return html.escape(str(value), quote=True)


def _counts(results: Sequence[ProbeResult]) -> dict[str, int]:
    findings = [f for r in results for f in r.findings]
    return {
        "confirmed": sum(1 for f in findings if f.confidence is Confidence.CONFIRMED),
        "suspicious": sum(1 for f in findings if f.confidence is Confidence.SUSPICIOUS),
        "informational": sum(1 for f in findings if f.confidence is Confidence.INFORMATIONAL),
        "probes": len(results),
        "errored": sum(
            1 for r in results if r.status in (ProbeStatus.ERRORED, ProbeStatus.TIMED_OUT)
        ),
        "skipped": sum(1 for r in results if r.status is ProbeStatus.SKIPPED),
    }


def _tile(label: str, number: int, css: str = "") -> str:
    return (
        f'<div class="tile"><span class="n {esc(css)}">{number}</span>'
        f'<span class="l">{esc(label)}</span></div>'
    )


def _finding_block(finding: Finding, *, include_evidence: bool) -> str:
    tier = finding.confidence.value
    parts = [
        f'<article class="finding {esc(tier)}">',
        '<div class="badges">',
        f'<span class="badge {esc(tier)}">{esc(tier)}</span>',
        f'<span class="badge plain">{esc(finding.severity.value)}</span>',
        f'<span class="badge plain">{esc(finding.category.value)}</span>',
        "</div>",
        f"<h3>{esc(finding.title)}</h3>",
        f'<p class="sub" style="margin:0 0 .5rem">{esc(finding.probe_id)}</p>',
        f"<p>{esc(finding.description)}</p>",
    ]

    if finding.proof is not None:
        parts.append(
            f'<div class="proof"><strong>Proof</strong> '
            f"({esc(finding.proof.kind.value)} in {esc(finding.proof.location)})<br>"
            f"{esc(finding.proof.detail)}</div>"
        )
    else:
        # Say plainly that nothing was proven. A reader skimming a report should not
        # have to infer it from the absence of a proof block.
        parts.append(
            '<p class="caveat">Not confirmed: a heuristic matched but no verifiable '
            "proof was obtained. Review the transcript before acting on this.</p>"
        )
    if finding.signals:
        signals = ", ".join(esc(s) for s in finding.signals)
        parts.append(f'<p class="sub" style="margin:.25rem 0">Signals: {signals}</p>')

    if include_evidence:
        parts.append(
            "<details><summary>Transcript</summary>"
            f"<pre>{esc(finding.evidence.prompt)}</pre>"
            f"<pre>{esc(finding.evidence.response)}</pre></details>"
        )

    parts.append("</article>")
    return "".join(parts)


def _probe_table(results: Sequence[ProbeResult]) -> str:
    rows = []
    for result in sorted(results, key=lambda r: r.probe_id):
        detail = result.error or result.detail or ""
        rows.append(
            f"<tr><td>{esc(result.probe_id)}</td>"
            f'<td class="status-{esc(result.status.value)}">{esc(result.status.value)}</td>'
            f"<td>{result.attempts}</td><td>{result.duration_ms} ms</td>"
            f"<td>{esc(detail)}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Probe</th><th>Status</th><th>Requests</th>"
        "<th>Duration</th><th>Detail</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def render_report(
    results: Sequence[ProbeResult],
    *,
    target: str,
    scan_id: str | None = None,
    generated_at: datetime | None = None,
    include_evidence: bool = True,
    seeded: Sequence[Mapping[str, str]] = (),
) -> str:
    """Build a complete, self-contained HTML document for a scan.

    ``seeded`` takes display-ready records rather than :class:`Canary` objects, because
    the values stored with a scan are already redacted and re-redacting them would
    mangle the output.
    """
    counts = _counts(results)
    when = generated_at or utcnow()
    findings = sorted(
        (f for r in results for f in r.findings),
        key=lambda f: (_CONFIDENCE_ORDER[f.confidence], _SEVERITY_ORDER[f.severity]),
    )

    body = [
        "<main>",
        "<h1>PromptSentinel report</h1>",
        f'<p class="sub">{esc(target)}',
        f" &middot; scan {esc(scan_id)}" if scan_id else "",
        f" &middot; {esc(when.strftime('%Y-%m-%d %H:%M UTC'))}</p>",
        '<div class="tiles">',
        _tile("confirmed", counts["confirmed"], "confirmed"),
        _tile("suspicious", counts["suspicious"], "suspicious"),
        _tile("informational", counts["informational"], "informational"),
        _tile("probes run", counts["probes"]),
        _tile("errored", counts["errored"], "confirmed" if counts["errored"] else "ok"),
        _tile("skipped", counts["skipped"]),
        "</div>",
    ]

    if counts["errored"] or counts["skipped"]:
        # The caveat goes above the findings, not in a footnote. "No findings" means
        # something very different when probes never ran.
        body.append(
            f'<div class="notice"><strong>Incomplete coverage.</strong> '
            f"{counts['errored']} probe(s) failed and {counts['skipped']} were skipped. "
            "Attack paths they cover were not tested; see the probe table below.</div>"
        )

    if include_evidence:
        body.append(
            '<div class="notice"><strong>Contains transcripts.</strong> This report '
            "includes prompts and responses from the target application, which may "
            "include its system prompt. Treat it as sensitive.</div>"
        )

    body.append("<h2>Findings</h2>")
    if findings:
        body.extend(_finding_block(f, include_evidence=include_evidence) for f in findings)
    else:
        body.append("<p>No findings.</p>")

    body.append("<h2>Probes</h2>")
    body.append(_probe_table(results))

    if seeded:
        body.append("<h2>Seeded values</h2>")
        body.append(
            '<p class="sub">Synthetic secrets planted during this scan. None are real; '
            "values are truncated.</p>"
        )
        rows = "".join(
            f"<tr><td>{esc(c.get('label', ''))}</td>"
            f"<td>{esc(c.get('placement', ''))}</td>"
            f"<td>{esc(c.get('value', ''))}</td></tr>"
            for c in seeded
        )
        body.append(
            "<table><thead><tr><th>Label</th><th>Placement</th><th>Value</th></tr>"
            f"</thead><tbody>{rows}</tbody></table>"
        )

    body.append(
        f"<footer>Generated by PromptSentinel {esc(__version__)}. "
        "Confirmed findings are backed by verifiable proof; suspicious findings are "
        "heuristic and require review.</footer>"
    )
    body.append("</main>")

    return page(f"PromptSentinel report - {target}", "".join(body))
