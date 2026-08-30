# Source tools

The source layer exposes semantic, bounded operations—never a generic shell.

| Tool | Requirement | Purpose |
|---|---|---|
| Git | required | pin refs, history, diff, inert archive snapshots |
| ripgrep | required | exact/sibling search |
| Semgrep | optional | structural variants using program-local validated rules |
| CodeQL | optional | deep dataflow over a prebuilt or sandbox-created program-local database |
| Gitleaks | optional | redacted secret-candidate observations |
| TruffleHog/NoseyParker | optional | detected future secret-scanner capability |
| OSV-Scanner | optional | advisory observations for reachability triage |

```bash
./harness source detect
./harness source install-guide
```

Missing optional tools produce warnings, not false readiness or automatic
installation. Prefer ripgrep for exact siblings, Semgrep for structural pattern
expansion, CodeQL for justified cross-function flow, Git for patch/root-cause
work, Burp for observed traffic, and the Broker for runtime validation.
