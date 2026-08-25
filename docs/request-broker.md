# Request broker

The broker (`bughunt_harness/requests/broker.py`) is the **only** sanctioned
external HTTP path. Arbitrary unrestricted execution is never exposed; a raw
`requests.request` against an unvetted target does not exist downstream.

Every request flows through, in order:

1. **Scope check** — out-of-scope targets are refused immediately (no network).
2. **Policy gate** — `deny` refuses; `approval_required` records an approval
   request and returns without sending.
3. **Header/secret resolution** — required + secret headers are resolved from
   `env:` / `keyring:` / `file:` references (values never logged).
4. **Rate limit** — per-host minimum-spacing enforced against `roe.max_rps`.
5. **Burp proxy routing** — optional, from `BUGHUNT_BURP_PROXY`.
6. **Execution** — via `requests`, with safe defaults (redirects off, verify on).
7. **Redaction** — response headers + body preview are redacted.
8. **Evidence persistence** — a redacted `request_response` record is written to
   the program's `evidence/` dir.
9. **Action log** — records action/target/decision/summary (no secrets).

## Result

`BrokerResult` carries `ok`, `decision` (allow / approval_required / deny),
`reason`, `status_code`, redacted headers, a bounded `body_preview`, and the
`evidence_id`.

## The MCP + CLI surface

- MCP: `send_authorized_http_request(target, method, action, headers, body,
  json_body, params)` — one request per call (scope, policy, rate-limit, and
  redaction are enforced inside the broker).
- CLI: the broker is invoked through the MCP server and program-context helpers;
  there is deliberately no "curl-like" raw CLI escape hatch.

## Safety properties

- Out-of-scope / forbidden / approval-gated requests **short-circuit before any
  socket is opened** (asserted in `tests/test_broker.py`).
- The happy path is only exercised in tests against a **loopback** fixture
  server — never a real target (spec §95).