# Security Policy

## Intended use

PromptSentinel is a security testing tool for LLM applications **you own or are
explicitly authorized to test**. It generates adversarial prompts, attempts to extract
system prompts, and tries to trigger unauthorized tool calls. Used against a system you
do not control, that is unauthorized access.

Every scan requires an attestation of authorization, recorded with the scan. The tool
refuses to run without it. Do not remove that gate.

## What the tool will not do

- Scan a target without a recorded authorization attestation
- Discover or enumerate targets — you supply the endpoint
- Send evidence or transcripts to a webhook; completion callbacks carry counts only

## Handling of secrets

- Target API keys are held as `SecretStr` and are **never** written to the database.
  Persisted target specs are serialized in JSON mode, which redacts them.
- Canary values in reports are truncated: enough to correlate, not enough to replay.
- Scan reports contain prompts and responses from your application, which may include
  your real system prompt. Treat a report as sensitive.

## Reporting a vulnerability

Open a private security advisory on the repository. Please do not file a public issue
for a vulnerability in PromptSentinel itself.
