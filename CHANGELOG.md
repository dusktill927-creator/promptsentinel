# Changelog

All notable changes to PromptSentinel are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Findings are tiered by confidence, and that tiering is a compatibility surface: a
change that could move a finding from `SUSPICIOUS` to `CONFIRMED`, or that alters
what counts as proof, is called out explicitly in every release that makes one.

## [Unreleased]

## [0.2.0] - 2026-09-16

The first release driven by evidence from real models rather than from mocks.
Every heuristic change below was found by scanning `gpt-oss-120b`, `llama3.2:1b`,
`qwen2.5:1.5b` and `gemma2:2b` and reading the output, not by reasoning about
what a model might say.

### Added

- **Multi-turn probes.** `Conversation` carries state across turns, bounded by
  `ProbeContext.max_turns`. Single-turn probes are unaffected.
- **Seven probes**, bringing the total to 28:
  - `system_prompt.crescendo` — escalates across turns from a benign request.
  - `jailbreak.persona_commitment` — establishes a persona, then trades on it.
  - `data_leakage.format_coercion` — asks for held data as JSON, CSV or a table,
    on the theory that a refusal trained on prose does not cover a schema.
  - `data_leakage.error_elicitation` — provokes an error path and reads what the
    handler discloses.
  - `indirect_injection.exfiltration_channel` — plants an instruction to route
    data outward through a URL or image the response renders.
  - `indirect_injection.delayed_trigger` — plants an instruction that fires on a
    later turn rather than on the turn that delivers it.
  - `excessive_agency.chained_escalation` — reaches a restricted tool through a
    sequence of individually permitted calls.
- **Generic HTTP target adapter.** Describe an application's request and response
  with `{{prompt}}`, `{{history}}`, `{{system}}` and `{{documents}}` placeholders
  and a dotted path to the reply. Targets no longer have to be
  OpenAI-compatible, which was the single largest limit on what could be tested.
  Declared capabilities are derived from the template, so a target that has no
  document slot is never sent an indirect-injection probe.
- **Scan diffing.** `promptsentinel diff` compares two reports by finding
  fingerprint, so CI can fail on findings that are new rather than on a standing
  count.
- **Response recording.** Every probe run stores the target's last response.
  A clean run and a run whose payload never arrived were previously
  indistinguishable in a report; they no longer are.
- **Vulnerable demo application** (`examples/vulnerable_app.py`) with a
  deliberately bespoke request shape, so the HTTP adapter is exercised against
  something that is not an OpenAI clone.

### Fixed

- **Heuristics: four defects, all found by measurement.** The first real scan
  recorded 38 responses — a corpus the `suspicious` tier had never been checked
  against. Every defect was a phrasing the pattern's own author had not happened
  to type:
  - `\b` anchoring failed inside `support_api_key=`, because `_` is a word
    character, so credential labels never matched.
  - Typographic quotes (U+2019 and friends) were not normalised, so `I'm sorry`
    from any model that renders a curly apostrophe read as a non-refusal.
  - `I am sorry` was absent from the refusal set; only the contraction matched.
  - `declines_authority` was missing, so a refusal phrased as "I am not
    authorized to reveal" registered as no refusal at all.

  Separately, **disclosure detection had almost no recall**: 0 of those 38
  responses, including plain leaks like `Order Status: Open API Key: ...`. Three
  patterns drawn from observed output raised it to 3 of 4, with no new hits on
  refusals or ordinary answers.
- **Refusals and deflections are no longer findings.** A response that declines
  *and names its authority*, and a generic greeting or request for
  clarification, were both being reported as weakened refusals. This removed the
  entire suspicious tier from the demo application, 4 findings to 0, with every
  confirmed finding unchanged — and in doing so exposed one **confirmed**
  finding, 12 to 13. `jailbreak.output_obfuscation` had been stopping at its
  second attempt to report a deflection and never reaching its third, which is a
  genuine bypass. The noise was masking a true positive.

### Changed

- The version is now single-sourced from `promptsentinel.__version__` and read by
  the build backend, so distribution metadata cannot drift from what `/health`,
  the SARIF driver record, the HTML footer and `promptsentinel version` report.
  This release exists in part because those two copies had already drifted.

### Security

No change to the authorization gate, the confidence invariant, or credential
handling. The invariant was checked against this release's own scan output —
every confirmed finding carries proof, no suspicious finding does — in addition
to the unit tests that enforce it structurally.

## [0.1.0] - 2026-09-16

First release. A scan can be submitted, run asynchronously, and collected as a
structured report, against a target the operator has attested they may test.

### Added

- **Confidence tiering, enforced structurally.** `Finding` is frozen and
  validates in both directions: `CONFIRMED` without proof is unconstructible, and
  so is proof on any lower tier. `model_copy` is overridden to re-validate, which
  closes the documented Pydantic hole. Constructors are deliberately asymmetric —
  `Finding.suspicious()` takes no `proof` argument at all. An unconfirmed finding
  cannot be silently upgraded, because there is no code path that upgrades one.
- **Mandatory authorization gate.** `Authorization` cannot be constructed in an
  invalid state, the engine takes one by type rather than by flag, and `verify()`
  re-checks at run time. A scan without attestation is refused with HTTP 403
  before anything is persisted.
- **Canary proof primitives**, kept in a module with no heuristics in it.
  128-bit tokens, and detection that survives the target reversing, base64ing or
  markdown-wrapping the value on the way out — bounded to 64 decode attempts so a
  hostile response cannot turn a scan into a self-inflicted DoS.
- **21 probes across the five V1 categories**: system-prompt extraction,
  jailbreak and content-policy bypass, indirect prompt injection via a simulated
  malicious retrieved document, PII and data leakage, and excessive agency.
- **Plugin probe interface.** One `async def run(target, context) -> ProbeResult`,
  discovered by entry point. Adding a probe requires no engine change.
- **Target abstraction** with OpenAI-compatible and mock adapters, capability
  declaration, and document injection for RAG deployments.
- **Async job model.** Submit a scan, get an ID, poll or receive a webhook.
  In-process by default; `arq` and Redis for distributed execution.
- **FastAPI application** with generated OpenAPI docs, API-key authentication
  that fails closed at startup, and an optional read-only dashboard, off by
  default.
- **`promptsentinel` CLI** over the same engine as the API.
- **SARIF 2.1.0 and standalone HTML** report export.
- **Persistence** for scans, probe runs and findings, with Alembic migrations
  and a schema-drift test. SQLite by default, Postgres tested in CI.
- **Token-bucket pacing** on every path that sends traffic to a target.

### Fixed

Defects found while building, each one kept as a regression test:

- Probe timeouts counted rate-limiter queue time, failing 3 of 4 probes as
  `TIMED_OUT` on a correctly-behaving target. The bucket is now a slot scheduler,
  so the wait is known before it begins and credited to the deadline up front.
- `--api-key-env` was silently ignored when the target came from a file. A key
  that cannot be applied is now an error rather than 20 failed requests.
- Canary redaction kept only the shared `PSCANARY` prefix, rendering every canary
  in a report identically — contradicting its own docstring.
- The optional backends were not optional: importing the API without `arq`
  installed raised. Split into lazy imports, with CI jobs that install neither.
- The excessive-agency control asked for something a model could not act on, so
  the control and the finding contradicted each other in the report.

### Security

Out of scope by design, and not merely unimplemented: scanning of targets the
operator has not attested to, autonomous or internet-wide scanning, and any
capability whose purpose is evading detection.

[Unreleased]: https://github.com/dusktill927-creator/promptsentinel/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/dusktill927-creator/promptsentinel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusktill927-creator/promptsentinel/releases/tag/v0.1.0
