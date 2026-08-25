# Evidence contract

An observation is evidence only if it is **durable and reproducible**.

- Every claim that matters has an evidence record pointing at a captured
  artifact on disk (request/response, command output, screenshot reference, file
  reference, observation, text).
- For HTTP findings, prefer `request_response` evidence — the full (redacted)
  request and response, enough for a third party to reproduce.
- Redact secrets and PII from *stored* evidence and previews.
- A finding without supporting evidence is not a finding; it is an opinion.
- Never fabricate evidence. If you did not observe it, do not claim you did.

## Capturing evidence

Evidence kinds live in `bughunt_harness/state/constants.py`
(`request_response`, `command_output`, `screenshot_reference`, `file_reference`,
`observation`, `text`).

- The request broker persists `request_response` evidence automatically on every
  allowed request (redacted headers/body + a preview under the program's
  `evidence/` dir).
- Use `evidence add` / the MCP tool to register manual artifacts.

## Reproducibility

A stored piece of evidence must let a fresh reviewer (or the adversarial
validator) re-run the controlled experiment. If the steps, target, account
role, and expected-vs-actual are recorded alongside, the evidence is complete.

Redaction runs in the broker (header + body patterns) and is supplemented by
manual `[REDACTED]` markers when residual secret values slip through.