# Quickstart

## One-time setup

```bash
source .venv/bin/activate
./harness init
npm install
./harness sync
./harness doctor
```

Configure Burp MCP at `http://127.0.0.1:9876`. The broker detects
`http://127.0.0.1:8080` only when that proxy listener is reachable; otherwise
set `BUGHUNT_BURP_PROXY` explicitly. Import the Burp CA into a dedicated
research browser profile, not a personal/global trust store.

## Per program

```bash
./harness program create acme --platform custom
# Edit ~/.bughunt/programs/acme/{program,scope,roe,headers,accounts,autonomy}.yaml
./harness engagement validate --program acme
./harness program activate --program acme
./harness policy matrix --program acme
./harness auth list --program acme
./harness doctor --program acme --deep
./harness hunt --program acme --goal report_ready
```

Resume by running the final command again; SessionStart loads the latest
checkpoint and current research state. Review results with:

```bash
./harness finding list --program acme
./harness checkpoint latest --program acme
./harness approval list --program acme
```

The workflow stops at `qa_passed`. Submission remains a human action.

## Imported program quickstart

```bash
./harness platform credential add hackerone researcher-main \
  --username-ref env:HACKERONE_API_USERNAME \
  --token-ref env:HACKERONE_API_TOKEN
./harness program import --platform hackerone --handle acme --credential researcher-main
./harness program review --program acme --interactive
./harness program approve-import --program acme
# Add required test-account AuthContext secret references locally.
./harness program activate --program acme
./harness doctor --program acme --deep
./harness recon run --program acme --profile standard
./harness start claude --program acme --autonomous
```

No imported program becomes active during fetch or parsing.
