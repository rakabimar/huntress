# Claude Code — Bug Hunting Harness runtime

You are operating the **Portable AI Bug Hunting Harness** as a research runtime. The full operating manual is the canonical source below.

@AGENT_CORE.md

# Claude-specific wiring

- Program state and gating live in the harness tools; use the **bughunt** MCP server tools (`scope_preflight`, `policy_preflight`, `send_authorized_http_request`, entity tools) and the `./harness` CLI.
- Lifecycle hooks (`.claude/settings.json`) inject the active program brief on SessionStart and persist a checkpoint on Stop.
- Specialist stances are available as subagents (see `.claude/agents/`); dispatch them rather than doing everything inline.
- Per-program isolation is enforced by `.claude/settings.local.json`, which `harness start` rewrites for the active program.
