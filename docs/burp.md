# Burp integration

The confirmed WSL-reachable Burp MCP endpoint is
`http://127.0.0.1:9876`. Doctor performs an MCP initialize/list-tools handshake;
an open TCP port alone is not a pass. Harness exposes scoped read operations for
proxy HTTP/WebSocket history and Organizer items. Installed Burp active-send
tools are not exposed as an uncontrolled target path.

The broker detects `http://127.0.0.1:8080` when reachable. Override explicitly:

```bash
export BUGHUNT_BURP_PROXY=http://127.0.0.1:8080
export BUGHUNT_BURP_MCP=http://127.0.0.1:9876
./harness doctor --program acme --deep
```

If the listener is unreachable, doctor reports it; no alternate listener is
guessed. Use one Burp project per program. Keep TLS verification enabled and
trust the Burp CA only in dedicated research browser profiles.
## Canonical endpoints, proxy identity, and TLS trust

The known Burp MCP endpoint is `http://127.0.0.1:9876`; it is distinct from the
Proxy listener. Configure interception explicitly:

```yaml
integrations:
  burp:
    mcp_url: http://127.0.0.1:9876
    proxy_url: http://127.0.0.1:8080
    ca_bundle: ~/.bughunt/certs/burp-ca.pem
    https_interception: true
```

Per-program `integrations.yaml` overrides global `~/.bughunt/config.yaml`,
which overrides `BUGHUNT_BURP_PROXY`, `BUGHUNT_BURP_MCP`, and
`BUGHUNT_BURP_CA`. An open port 8080 is reported only as an unverified
candidate and never enables proxying. Doctor reports configured, reachable,
verified, MCP reachable, and CA status separately.

When interception is active the Broker passes the validated PEM path as the
Requests `verify` value. It never uses `verify=False`, never edits the system
trust store, and fails closed when HTTPS interception is declared without a
usable CA.

