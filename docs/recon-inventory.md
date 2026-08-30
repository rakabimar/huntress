# Recon inventory

Schema v4 adds seven compact tables to each program's existing `hunt.db`:
`recon_run`, `asset`, `asset_observation`, `endpoint`,
`endpoint_parameter`, `technology_observation`, and `recon_change`.

Assets are unique by type and normalized value. Endpoints are unique by host,
scheme, method, and conservative path shape. Query/body parameter names are
stored, never their values. Observations preserve tool/source/run provenance,
so subfinder, amass, Burp, JS, and archives can enrich one identity.

```bash
./harness recon runs --program acme
./harness recon show --program acme RECON-001
./harness recon diff --program acme RECON-001 RECON-002
./harness recon assets --program acme --new
./harness recon endpoints --program acme --interesting --min-score 60
./harness recon parameters --program acme --host api.example.com
./harness recon technologies --program acme
./harness recon changes --program acme
```

All list commands are bounded. Interest scores are deterministic research
priority (0–100), not severity. Stored reasons expose the exact scoring signals.
