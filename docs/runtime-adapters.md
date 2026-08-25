# Runtime adapters & sync

`bughunt_harness/adapters/` translates the canonical sources —
`AGENT_CORE.md`, `agent-specs/`, `skills/` — into each runtime's native config
so Claude Code, Codex, and OpenCode behave identically.

## `harness sync`

Regenerates, per runtime:

- **Claude Code** — `CLAUDE.md` (wrapper `@AGENT_CORE.md`), `.claude/settings.json`
  (permissions + lifecycle hooks), `.mcp.json` (registers `bughunt`), agent specs,
  and skill symlinks.
- **Codex** — `AGENTS.md` (inlines the canonical core) + `.codex/config.toml` +
  `.codex/agents/`.
- **OpenCode** — `AGENTS.md` + `opencode.json` + `.opencode/agent/`.

```bash
./harness sync                 # all runtimes
./harness sync --runtime claude
```

## Lifecycle hooks

Three hooks are wired into the runtime config, each reading a JSON payload on
stdin and printing JSON on stdout:

- **SessionStart** — inject the active program's compact brief (scope summary,
  ROE flags, accounts-as-metadata, current lead/hypotheses).
- **PreToolUse** (`Bash`) — backstop: deny dangerous commands (`rm -rf /`,
  `git push`, `curl … | sh`, raw network tools against non-fixture hosts).
- **Stop** — end the current session and persist a checkpoint.

## Session binding & isolation

`harness start` writes `.claude/settings.local.json` (never committed) that:

- adds the active program's workspace as an `additionalDirectory`;
- grants read/edit only there;
- **denies** every other program workspace plus all secret locations.

This is the mechanism that makes "one program per session" a hard technical
boundary, not a note in a brief.