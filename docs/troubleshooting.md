# Troubleshooting

Run the narrow check first, then deep program readiness:

```bash
./harness doctor
./harness doctor --program acme --deep
```

- `program_present` fails: validate configuration, activate normally, and
  ensure `autonomy.enabled: true` plus `roe.automation_allowed: true`.
- `adapters` fails after moving the repository: run `./harness sync`.
- Burp Proxy fails: start/configure the listener or set
  `BUGHUNT_BURP_PROXY`; the harness will not guess another port.
- Burp MCP fails: keep Burp running and verify WSL can reach
  `http://127.0.0.1:9876`; doctor checks the MCP handshake.
- Playwright fails: run `npm install`, verify Chromium exists, and rerun deep
  doctor. Browser profiles are program/account-specific.
- Burp CA warns: import Burp's CA into the dedicated research browser only,
  verify HTTPS, then create `browser/BURP_CA_TRUSTED` in that program.
- AuthContexts fail: resolve each `env:`, `keyring:`, or protected `file:` ref;
  `./harness auth list --program acme` reveals availability only.
- ASK pauses: inspect and decide the bounded plan with `approval list/show` and
  `approval approve|reject`. The AI cannot decide it.
- A prior session stopped: inspect `checkpoint latest`; restarting autonomous
  mode loads persisted research state rather than relying on chat memory.
## Readiness meanings

Doctor reports a ladder and a separate model gate:

- `ENV_READY`: Python, dependencies, and writable harness state work.
- `CORE_READY`: state, scope, policy, Broker invariants, and migrations work.
- `HUNT_READY`: an active, valid, scoped program can perform controlled research.
- `FULL_READY`: configured Burp, Playwright mediation, recon, validation, and output integrations pass deep checks.
- `MODEL_VERIFIED`: a real configured model completed the local acceptance hunt. It is `NOT_RUN` unless explicitly requested.

Missing optional deep-recon binaries are warnings and do not downgrade core
readiness. Missing integrations required for the requested deep/full level are
reported individually rather than hidden behind a module-exists PASS.
