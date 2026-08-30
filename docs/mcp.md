# MCP architecture

The canonical registry is `mcp/registry.yaml`; `./harness sync` generates
runtime-specific configuration.

- Harness MCP is the state and controlled active-execution plane. It exposes
  intent-specific scope, policy, research, evidence, approval, validation,
  checkpoint, recon, and broker tools—never SQL, shell, or unrestricted update.
- Burp MCP at `http://127.0.0.1:9876` is the read-oriented observation plane.
  Harness wrappers retain only scoped, redacted, untrusted target data.
- Microsoft Playwright MCP is the stateful browser plane. Config is generated
  per program and account.

Every Harness MCP write binds program, exact session, runtime, agent role, tool,
and timestamp where applicable. A normal researcher cannot submit a supported
validation review; a separate `finding-validator` session must do so.

Recon is exposed as intent: `run_recon_profile`, `run_recon_stage`,
`get_recon_status`, `list_recon_runs`, `get_recon_run`, `list_assets`,
`get_asset`, `list_endpoints`, `get_endpoint`, `list_endpoint_parameters`,
`list_recon_changes`, `list_interesting_surfaces`, `get_recon_summary`,
`promote_surface_to_lead`, and `ingest_burp_recon`. Raw scanner flags and shell
commands are not MCP tools.

```bash
./harness mcp status
./harness mcp serve
./harness sync
```
## Role-filtered tool surfaces

`BUGHUNT_AGENT_ROLE` filters one canonical MCP backend at registration time.
Orchestrator/researcher roles receive research-loop, concise recon, Broker,
approval-request, checkpoint, and policy-mediated browser tools. Recon
specialists receive inventory and read-plane tools. Finding validators receive
only finding-linked bundles/evidence, one bounded replay path, and structured
review submission. Reporters receive finding/validation/evidence and
PoC/CVSS/report/QA tools, with no recon or mutation execution.

Researchers cannot submit validator reviews; validators cannot decide ASK
approvals; reporters cannot run recon or browser mutations. `manual` and
`debug` are the explicit compatibility roles retaining the complete backend.
