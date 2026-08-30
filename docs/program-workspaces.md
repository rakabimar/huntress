# Program workspaces

Each program lives under `~/.bughunt/programs/<slug>` and owns its own
`state/hunt.db`, evidence, recon artifacts, reports, Burp notes, and browser
profiles. The global registry contains only non-sensitive program metadata.

Claude startup sets `BUGHUNT_PROGRAM` and the exact `BUGHUNT_SESSION_ID`.
Hooks, MCP writes, broker requests, actions, reviews, and checkpoints must use
that session. Sibling workspaces and the global secret directory are denied in
the session binding.

Use one Burp project per bounty program. The Harness Burp integration filters
returned traffic through the active program's scope, but separate Burp projects
remain the strongest practical isolation boundary.

Do not commit workspace exports, evidence, reports, cookies, or target data.

## Intake artifacts

Imported source snapshots live only in `intake/IMPORT-NNN/` inside the bound program workspace. `intake/protective-overlay.yaml` is the fail-safe runtime restriction produced by material refresh changes. Intake artifacts are excluded from non-sensitive program exports and repository ignore rules cover accidental workspace copies.
