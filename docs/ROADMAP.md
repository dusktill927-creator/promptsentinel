# Roadmap

## Phase 0 — End-to-end skeleton ✅

Repo structure, FastAPI app, `Probe` interface, plugin registry, target abstraction,
persistence, async job model, authorization gate, one diagnostic probe, green pytest
and GitHub Actions CI.

The slice proves the pipeline: submit a scan → it runs in the background → a canary is
seeded → the leak is confirmed by proof → a report comes back over HTTP.

## Phase 1 — The five V1 probe categories

Built one at a time, each with the three-outcome test pattern established by
`tests/unit/test_diagnostic_probe.py` (proven leak / plausible-but-unproven / clean).

| # | Category | Confirmation strategy |
|---|---|---|
| 1 | System-prompt extraction | Canary seeded in the system prompt returned verbatim |
| 2 | Jailbreak / policy bypass | Marker token the model was told never to emit |
| 3 | Indirect prompt injection | Canary in a simulated retrieved document, exfiltrated |
| 4 | PII / data leakage | Canary "customer records" surfaced to an unauthorized asker |
| 5 | Unauthorized tool call | A disallowed tool actually invoked — structural, not textual |

Category 3 needs a `DOCUMENT_INJECTION` target mode so probes can supply a poisoned
document into the retrieval path. Category 5 needs the tool-offering path exercised
end to end; the `ToolCall` plumbing already exists for it.

Each category will want multiple techniques (a probe per technique, not per category),
which is exactly what the registry is for.

## Phase 2 — Operability

- **Alembic migrations** — before any external user's data depends on the schema.
- **CLI** (`promptsentinel scan --target ... --attest`) over the same engine, with the
  authorization gate enforced identically.
- **API authentication** — the API currently has none and must not be exposed to an
  untrusted network.
- **Rate limiting toward the target** — `max_concurrent_probes` bounds parallelism, but
  a token-bucket per target would be a stronger guarantee that a scan never resembles a
  denial-of-service against the operator's own application.
- **Postgres in CI** — the code is written for it; CI should prove it.

## Phase 3 — Product surface

- Distributed job queue (ARQ/Redis) behind the existing `JobQueue` protocol, with a
  secrets backend for target credentials.
- Report export: SARIF (so findings land in GitHub code scanning) and HTML.
- A thin dashboard. API and CLI first — the dashboard should have no capability the API
  lacks.

## Explicitly out of scope

- Scanning arbitrary or unowned targets; any form of target discovery
- Autonomous or internet-wide scanning
- A fine-tuned ML detection model — rule- and canary-based confirmation first
- Billing, multi-tenancy
