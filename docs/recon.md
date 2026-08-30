# Recon and attack-surface intelligence

Recon is a persistent pipeline, not a shell wrapper or URL dump:

```text
scope -> discovery -> normalization -> inventory -> enrichment
      -> correlation -> changes -> interest scoring -> contextual leads
```

Run the normal profile after activating and checking a program:

```bash
./harness recon detect
./harness doctor --program acme --deep
./harness recon run --program acme --profile standard
./harness recon summary --program acme
./harness recon interesting --program acme
```

For diagnostics, run one stage with optional explicit in-scope seeds:

```bash
./harness recon run --program acme --stage passive
./harness recon run --program acme --stage crawl --seed https://app.example.com
```

Wildcard roots are passive discovery seeds only. With `*.example.com`, the
harness may query passive tools for `example.com`, while the ordinary Scope
Engine still blocks active requests to the root unless it is separately
included.

Each run writes a manifest and redacted raw artifacts under
`PROGRAM/recon/runs/RECON-NNN/`. Normalized records and provenance live in the
program's existing `hunt.db`. Scanner matches remain observations/Leads and
never become Findings.

See [recon profiles](recon-profiles.md), [tool support](recon-tools.md),
[inventory](recon-inventory.md), and [safety](recon-safety.md).
## Detector, scaling, and research reprioritization

Tool detection enumerates every executable candidate across PATH (plus the
common user-local bin directory), safely probes identities, rejects name
collisions such as Python HTTPX, and continues until ProjectDiscovery httpx is
found. Diagnostics retain every candidate and rejection reason.

Summary totals are SQL `COUNT` queries and remain accurate beyond listing
caps. Lists accept offset-based pagination. Scoring walks the full inventory in
batches. Bounded JavaScript parsing extracts routes, REST/GraphQL/WebSocket
paths, source-map hints, route/parameter names, identity/upload surfaces, and
in-scope host hints into canonical endpoint inventory without treating strings
as secrets.

Meaningful `ReconChange` rows such as a new object/role parameter update and
reprioritize an existing Lead. A closed Lead may be requeued only through a
durably linked ReconChange, preventing duplicate-spam while preserving new
research signal.
