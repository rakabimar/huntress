# Secrets & credentials

Credentials are **never** stored in the Git repository or in plaintext YAML.
A `secret_ref` points to one of (in preference order):

| Ref | Meaning | Example |
|---|---|---|
| `env:VARNAME` | environment variable | `env:BUGHUNT_H1_TOKEN` |
| `keyring:SERVICE/USER` | OS keyring entry | `keyring:hackerone/alice` |
| `file:NAME` | protected file under `~/.bughunt/secrets/<program>/NAME` | `file:id_token` |

## Rules

- A `secret_ref` must be a *reference*, never a bare value — the manager rejects
  plaintext loudly (`SecretError`).
- Only **metadata** (whether a credential is available) is surfaced to the
  model via `account_summaries`; values are resolved only inside the request
  broker, which redacts them from logs, evidence, and previews.
- Secret files are written with restrictive permissions (`0600`, best-effort on
  non-POSIX filesystems like WSL `/mnt/c`).
- `.gitignore` excludes `.env`, `*.key`, `*.pem`, `*secret*`, `*credential*`,
  `*_token*`, and the secrets directory.

## Program isolation for secrets

`~/.bughunt/secrets/<program>/` is per-program, and the session binding denies
`.claude/settings.local.json` reads of the secrets directory. Secret resolution
is always scoped to the active program's slug.

## Guardrails

- The `.claude/settings.json` deny list blocks `Read`/`Edit` of
  `~/.bughunt/secrets/**`, `~/.ssh/**`, `~/.aws/**`, `~/.gnupg/**`, and
  `~/.netrc`.
- If a secret value leaks into captured content, redact it (the broker's
  redactor runs automatically; add manual `[REDACTED]` markers for residuals).