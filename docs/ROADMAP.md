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
| 1 | System-prompt extraction ✅ | Canary seeded in the system prompt returned verbatim |
| 2 | Jailbreak / policy bypass ✅ | Marker token the model was told never to emit |
| 3 | Indirect prompt injection ✅ | Canary in a simulated retrieved document, acted upon |
| 4 | PII / data leakage ✅ | Canary "customer records" surfaced to an unauthorized asker |
| 5 | Unauthorized tool call | A disallowed tool actually invoked — structural, not textual |

Category 5 needs a way for a scan to declare which tools are disallowed, plus the
tool-offering path exercised end to end; the `ToolCall` plumbing already exists for it.

Each category gets multiple techniques (a probe per technique, not per category),
which is exactly what the registry is for.

**Category 3 shipped** with four techniques: `plain_instruction`,
`fake_system_block`, `hidden_markup` and `metadata_directive`. It required the first
real groundwork of the phase -- `Document`, a `documents=` argument to `Target.send()`,
and operator-supplied retrieval templates, so the injected text lands where that
application's own retriever would put it.

It also forced `Target.capabilities` from a ClassVar into an instance property.
Capability depends on configuration, not only on type: the same adapter is a RAG target
when retrieval is described and a plain chat target when it is not.

Its distinctive judgement is **obedience versus quotation**. A model that repeats an
injected instruction has not necessarily followed it, so a payload arriving wrapped in
the instruction's own wording is downgraded to SUSPICIOUS. The check splits the
instruction at the payload and tests each surrounding segment: comparing against the
whole instruction would match a target that obeyed perfectly, and comparing against the
instruction with the payload deleted would match a quoting target almost never.

**Category 4 shipped** with four techniques: `cross_customer_access`,
`bulk_extraction`, `pretext_impersonation` and `context_laundering`. It contributed the
**negative control**: the probe first asks for data it *should* be given, so that a
clean result distinguishes "no leak" from "the target never read our context". Reported
INFORMATIONAL when the control fails.

It also established that severity models are per-category, not global. Jailbreak treats
an unenforced control as less severe than a defeated one; data leakage treats trivially
reachable exposure as the most severe outcome. The difference is whether the finding is
about the control or about the data.

**Category 2 shipped** with four techniques: `roleplay_persona`,
`hypothetical_framing`, `authority_override` and `output_obfuscation`. It contains no
harmful payloads: the forbidden output is a random marker seeded into the operator's own
system prompt, which tests the rules the operator actually wrote rather than the base
model's safety training.

Its one novel piece of machinery is the **baseline request**. Each probe asks plainly
before it attacks, so "the policy was defeated" and "the policy was never enforced" are
reported as different findings with different severities. Later categories should copy
this: a probe that cannot tell a broken control from an absent one is not diagnostic.

**Category 1 shipped** with four techniques: `direct_request`, `delimiter_injection`,
`completion_priming` and `transformation`. It required no engine change — the four
files registered themselves through discovery, which was the first real test of the
plugin claim.

It also produced two pieces of shared machinery the later categories inherit:

- **Encoding-aware canary detection.** Asking for a base64 or reversed copy defeats a
  filter that only blocks verbatim repetition, and defeats a scanner that only looks
  for the literal token. Detection now decodes before matching; because every transform
  is deterministic and lossless, a match after decoding is still exact, so it stays on
  the proof side of the line.
- **`verbatim_span_length()`**, reporting when a response echoes a long contiguous span
  of the operator's own prompt. Deliberately a SUSPICIOUS signal rather than a proof —
  a system prompt can contain boilerplate the model already knows.

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
