# Request broker

The broker (`bughunt_harness/requests/broker.py`) is the **only** sanctioned
external HTTP path. Arbitrary unrestricted execution is never exposed; a raw
`requests.request` against an unvetted target does not exist downstream.

Every request flows through, in order:

1. **Scope check** — out-of-scope targets are refused immediately (no network).
2. **Policy gate** — `DENY` refuses; `ASK` uses only a matching bounded human
   approval; `AUTO` proceeds without creating approval state.
3. **Header/AuthContext resolution** — required + secret headers, cookie,
   bearer, or header bundles are resolved from
   `env:` / `keyring:` / `file:` references (values never logged).
4. **Rate/concurrency lease** — shared SQLite enforcement with expiring leases.
5. **Burp proxy routing** — optional, from `BUGHUNT_BURP_PROXY`.
6. **Execution** — via `requests`, TLS verification on. Redirects are handled
   manually and every hop repeats scope, policy, and rate checks.
7. **Redaction** — built-in headers, program secret headers, AuthContext headers,
   URL parameters, resolved values, and configured patterns are redacted.
8. **Evidence persistence** — a full redacted request/response representation is written to
   the program's `evidence/` dir.
9. **Action log** — records action/target/decision/summary (no secrets).

## Result

`BrokerResult` carries `ok`, `decision` plus `mode` (`AUTO` / `ASK` / `DENY`),
`reason`, `status_code`, redacted headers, a bounded `body_preview`, and the
`evidence_id`.

## The MCP + CLI surface

- MCP: `send_authorized_http_request(target, method, action, headers, body,
  json_body, params)` — one request per call (scope, policy, rate-limit, and
  redaction are enforced inside the broker).
- CLI: the broker is invoked through the MCP server and program-context helpers;
  there is deliberately no "curl-like" raw CLI escape hatch.

## Safety properties

- Out-of-scope / forbidden / unapproved ASK requests **short-circuit before any
  socket is opened**.
- The happy path is only exercised in tests against a **loopback** fixture
  server — never a real target (spec §95).
