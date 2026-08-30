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

The current Claude lifecycle is wired with exact-session binding:

- **SessionStart** — inject the active program's compact brief (scope summary,
  ROE flags, accounts-as-metadata, current lead/hypotheses).
- **PreToolUse** (`Bash`) — backstop: deny dangerous commands (`rm -rf /`,
  `git push`, `curl … | sh`, raw network tools against non-fixture hosts).
- **PostToolUse/PostToolUseFailure** — record model-safe action provenance.
- **PreCompact/Stop/SessionEnd** — persist a current-state checkpoint; only the
  exact `BUGHUNT_SESSION_ID` may close its session.

## Session binding & isolation

`harness start` writes `.claude/settings.local.json` (never committed) that:

- adds the active program's workspace as an `additionalDirectory`;
- grants read/edit only there;
- **denies** every other program workspace plus all secret locations.

This is the mechanism that makes "one program per session" a hard technical
boundary, not a note in a brief.

Claude direct network access is loopback-only. Codex is generated with
`approval_policy="never"`, workspace-write sandboxing, and network disabled;
OpenCode denies web fetch and generic Bash. Runtime versions are validated when
installed; absent secondary runtimes are reported generated but unverified.
