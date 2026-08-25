---
name: sqli
description: Use when testing inputs, filters, sort keys, or endpoints that may interpolate user data into SQL queries.
maturity: draft
risk_class: R2
category: injection
cwe: [89]
---

# SQL Injection

## Purpose
SQL injection occurs when attacker-controlled data is concatenated into a SQL statement, letting input alter query structure rather than merely its values. It often yields the highest-impact findings because it can bypass authentication, expose stored data, or subvert authorization boundaries. Bug hunters should aim to prove the parser confusion with the smallest possible effect, then stop.

## When to use
- Query parameters, form fields, path segments, sort/order columns, or JSON API inputs are reflected in queries.
- Application behavior differs based on a single character (`'`, `"`, `)`, `#`, `--`) in an input.
- Features that search, filter, sort, or page over database-backed data.
- Any place a value is stored and later reused in another query (second-order sites).

## Process
1. Identify an input that plausibly reaches a SQL string and note its boundary (WHERE clause, ORDER BY, INSERT, etc.).
2. Record a falsifiable hypothesis with `create_hypothesis`, e.g. "a trailing quote in the `id` parameter breaks statement parsing and flips the result set."
3. Before sending anything, confirm scope with `scope_preflight` and behavior risk with `policy_preflight`.
4. Run the minimal controlled experiment through `send_authorized_http_request` only, never raw `curl`/`sqlmap`. Start read-only: add `'` and observe, then a tautology/contradiction pair (`1=1` vs `1=0`) and watch whether results flip.
5. Classify the channel: error revealed, timing delta, boolean flip, or out-of-band callback — and choose the least-invasive indicator for each.
6. Record each observation with `complete_research_test` and persist redacted request/response as evidence via `create_evidence`.
7. For second-order inputs, store one payload, then trigger the downstream query that reads it before drawing any conclusion.

## Evidence
- `request_response` showing the raw request and the differing response for a boolean pair.
- `observation` noting a timing delta or a SQL error that echoes the parser position.
- `command_output` only for broker/CLI results, always with secrets and any PII redacted.

## False positives
- A reflected quote in an error page that never reaches SQL (e.g. JSON or template error) is not injection.
- A boolean flip caused by application logic or an unexpected empty result set, not query-structure change.
- WAF or firewall normalization that blocks the probe does not equal the vulnerability being patched.
- Numeric keys that ignore string suffixes produce no error, which is a type coercion, not an injection.

## Stop conditions
- `scope_preflight` rejects the target or `policy_preflight` denies the action — stop immediately.
- The proof would require R3/R4 behavior or destructive writes and no human approval is recorded.
- Demonstrating the flaw would read or write beyond a single controlled row — stop and report the minimal proof.
- Success would need mass data exfiltration or persistence to show impact — do not proceed.

## Example
On `http://example.test/api/orders?status=active`, hypothesize the `status` value is concatenated into a WHERE clause. Send `status=active'` and observe a SQL error (error-based). Then send `status=active' OR '1'='1` versus `status=active' AND '1'='0`; one returns all rows and the other none, flipping the count read-only. Record both responses, mark the hypothesis supported, and stop without extracting table contents.