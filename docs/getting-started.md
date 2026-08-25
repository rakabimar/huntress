# Getting started

## Prerequisites

- Python ≥ 3.10 (developed against 3.13)
- A Unix-like shell (bash/zsh); WSL2 supported
- Optional (for MCP + CVSS): `pip install 'mcp>=1.0,<2.0' cvss`

## 1. Bootstrap

```bash
cd bug_bounty
./scripts/bootstrap.sh
```

The script creates `.venv`, installs the package in editable mode with all
dependencies (including `mcp` and `cvss`), and seeds a synthetic `acme-test`
program whose scope is limited to `example.test` fixtures (spec §81/§95: no real
targets are ever touched during setup or testing).

## 2. Verify readiness

```bash
./harness doctor
```

You are looking for `FULL_READY` (or at least `HUNT_READY`). If checks fail, run
`./harness sync` first — the generated runtime config files are what several
probes assert.

## 3. Create and start your program

```bash
./harness program create my-program --platform custom
```

Then edit `~/.bughunt/programs/my-program/scope.yaml` and `roe.yaml` to reflect
your **actually authorized** scope and rules. The template ships with
`example.test` placeholders — replace them before any real testing.

```bash
./harness engagement validate            # confirm the five engagement files parse
./harness scope check https://api.example.test
./harness policy check read_http https://api.example.test
./harness start claude --program my-program
```

`harness start` rewrites the session binding (`.claude/settings.local.json`)
so the session can only read/write *that* program's workspace.

## 4. Run the research loop

The loop is driven by the specialist stances (see
[agent-specs](agent-specs.md)) and recorded in the per-program store:

```bash
./harness lead add "possible IDOR on /users"
./harness hypothesis create "If account_a GETs /users/42 then account_b's record is returned"
./harness test add <hyp-id> "GET /users/42 as account_a, compare with account_b"
# …execute via the MCP broker…
./harness test complete <test-id> --observation "…" --result supports
./harness finding create "IDOR" --affected-target https://example.test/users/42
```

Every step is persisted, so another runtime (or later session) can pick up where
you left off.

## 5. Report (never auto-submit)

```bash
./harness finding validate <id>
./harness cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
./harness report generate <id>
./harness report qa <id>
```

The report pipeline prepares a report for **human** review. Submission is gated
on `human_approved`, which no model reaches itself.

## Next steps

- Read [`AGENT_CORE.md`](../AGENT_CORE.md) — the canonical operating manual.
- Skim [`architecture.md`](architecture.md) and
  [`scope-and-policy.md`](scope-and-policy.md).