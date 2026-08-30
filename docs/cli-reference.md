# CLI reference

`./harness <command> <subcommand> [options]`. Run `./harness <cmd> --help` for
flags. All commands respect `BUGHUNT_HOME`, `BUGHUNT_PROGRAMS_DIR`, and
`BUGHUNT_PROGRAM` (active program) environment variables.

## Global

| Command | Description |
|---|---|
| `harness init` | create the `~/.bughunt` layout and registry |
| `harness doctor [--program S]` | readiness self-check → one of NOT_READY / ENV_READY / CORE_READY / HUNT_READY / FULL_READY (exit 0 unless ENV_READY / NOT_READY) |
| `harness sync [--runtime claude\|codex\|opencode]` | regenerate runtime config from canonical sources |
| `harness start {claude,codex,opencode} [--program S]` | bind the session to one program and launch the runtime |
| `harness hook {session-start,user-prompt-submit,pre-tool-use,post-tool-use,stop,session-end,pre-compact}` | internal lifecycle-hook entry (invoked by runtime config) |

## Programs & engagement

- `program {create,list,show,use,archive,activate,export}`
- `engagement {validate,status}`

## Scope & policy

- `scope check <target>` — deterministic in/out-of-scope decision
- `policy check <action> [--target T]` — allow / approval_required / deny

## Research state

- `lead {list,show,add,claim,release,close}`
- `hypothesis {list,show,create,update}`
- `test {list,add,complete}`
- `evidence {add,list,show}`
- `checkpoint {save,show,latest}`
- `knowledge {list,promote,candidates,status}`

## Findings, scoring, reporting

- `finding {list,show,create,validate,adjudicate,reject,cvss}`
- `poc --finding F [--steps ...]` — document a minimal PoC and advance a finding `validated → poc_ready`
- `cvss <vector>` — print base score + severity (v3.1/v4.0)
- `report {generate,qa}`

## Skills

- `skill {list,validate,eval}`; `eval --behavioral [--ablation]` is an explicit,
  optional model run and is not part of pytest.

## Source / white-box

- `source detect|install-guide` — capability status without installing tools.
- `source add|list|show|update|changes` — program-isolated repository registry,
  commit pinning, and differential change summary.
- `source context|search|read` — compact persisted context and bounded static
  access to untrusted repository data.
- `source audit --analysis context|authorization|semgrep|codeql|dependencies|secrets`
  — observations and Source Leads only.
- `source prepare-dependencies|sandbox|create-codeql-database` — approved offline
  caches and fixed-template, isolated execution; no generic command string.
- `source observations|relate-service|map-runtime` — inspect source intelligence,
  register service evidence, and correlate routes across all recon endpoints.

No source command installs dependencies automatically, enables network by
default, builds outside the sandbox, or exposes a generic shell.

## MCP

- `mcp {status,serve}` — `serve` runs the stdio MCP server (registered in `.mcp.json`)

---

## Example session

```bash
./harness program create acme --platform custom
./harness program use acme
./harness scope check https://api.example.test          # ALLOWED
./harness policy check read_http https://api.example.test  # approval_required (auto off)
./harness lead add "open redirect on /logout"
./harness skill list | head
./harness sync
```

Exit codes follow `bughunt_harness/errors.py`: 2 = program not found, 3 = no
active program, 4 = engagement invalid, 5 = approval required, 6 = action
forbidden, 7 = illegal state transition, 8 = network safety, 9 = program
inactive.

## Program intake commands

`harness platform status` and `harness platform credential add|list` manage adapter visibility and reference-only credentials.

`harness program import`, `intake-status`, `review`, `ambiguities`, `ambiguity resolve`, `approve-import`, `refresh`, `diff`, and `provenance` implement the human-gated intake lifecycle. `approve-import` is interactive and defaults to no. Agent-facing MCP intentionally has no approval, activation, credential-changing, or ambiguity-resolution tool.
