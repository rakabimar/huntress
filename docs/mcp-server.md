# Local MCP server

The harness ships a local stdio MCP server registered in `.mcp.json` as
`bughunt`. It exposes narrow, vendor-neutral tools so agents never manipulate
SQLite directly and every write retains provenance. There is deliberately **no**
generic `query_database` / `execute_shell` / `update_anything`.

## Run

```bash
./harness mcp status        # inspect registration/active program
./harness mcp serve         # stdio server (what the runtime launches)
```

The active program is resolved from `BUGHUNT_PROGRAM` (set by `harness start`)
or the active-program file. Program isolation is enforced inside
`load_program_context`.

## Tools

- **Context/scope/policy** — `get_active_engagement`, `get_scope_summary`,
  `scope_preflight(target)`, `policy_preflight(action, target)`.
- **Authorized HTTP** — `send_authorized_http_request(...)` (scope + policy +
  rate-limit + redaction enforced in the broker).
- **Leads** — `list_leads`, `get_lead`, `claim_lead`, `release_lead`.
- **Hypotheses** — `list_hypotheses`, `get_hypothesis`, `create_hypothesis`,
  `update_hypothesis`.
- **Tests** — `list_tests`, `create_research_test`, `complete_research_test`.
- **Evidence** — `create_evidence`, `list_evidence`.
- **Findings** — `list_findings`, `get_finding`, `create_finding_candidate`,
  `update_finding`.
- **State** — `get_hunt_status`, `get_latest_checkpoint`, `save_checkpoint`,
  `get_program_knowledge`, `list_leads`, `scope_preflight`, `policy_preflight`.

(The exact tool set is asserted by `harness doctor`'s `mcp_server` probe, which
builds the server and counts tools.)

## SDK version note

The server uses the FastMCP API from `mcp>=1.0,<2.0` (pinned `mcp==1.29.1`).
The 2.x line removed `mcp.server.fastmcp.FastMCP`; the dependency range in
`pyproject.toml` reflects that.