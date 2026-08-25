---
name: idor
description: Use when endpoints take object IDs, UUIDs, tenant scopes, or resource keys that might expose another principal's data
maturity: draft
risk_class: R2
category: authnz
cwe: [639]
---

# Insecure Direct Object Reference

## Purpose
IDOR is a broken access-control flaw where an application binds authorization to an object identifier (an integer id, UUID, slug, or tenant key) without verifying the caller is permitted to access it. By swapping or enumerating that identifier, an attacker reaches another principal's resource. For bug hunting it matters because it is the single most common high-impact authorization bug, and it is usually provable with a single read-only request.

## When to use
- Endpoints whose path or query includes `?id=`, `/users/123`, `account_id`, `tenant_id`, `orderId`, or file keys.
- Identifiers that are sequential integers, predictable slugs, or findable by enumeration rather than unguessable UUIDs.
- Two objects that differ only in an identifier where one belongs to another user or tenant, with no visible ownership check.

## Process
1. Identify the object reference and the boundary it should enforce (owner, tenant, role). Record this as a falsifiable claim with `create_hypothesis`.
2. Predict both outcomes: if authorization is enforced, the request returns the caller's own object or an access-denied; if broken, it returns another principal's object.
3. Acquire two distinct principals (two of your own test accounts) and the least-sensitive object you can prove with, preferably a read-only GET.
4. Run the minimal controlled experiment through `send_authorized_http_request` only, swapping the identifier from the second principal into the first principal's request. Never use raw curl/nmap/sqlmap.
5. Alternate a single identifier value at a time so the controlled change is unambiguous. Record each observation with `complete_research_test` and `create_evidence`.
6. If the other principal's object is returned, `update_hypothesis` to supported; if access is denied or the right object is returned, reject it.

## Evidence
- A `request_response` pair showing the modified identifier and the server returning another principal's data, distinct from the requesting account's own.
- An `observation` noting which identifier value changed and whose resource appeared in the body.
- `command_output` only for broker-mediated captures; redact tokens, emails, and PII before persisting.

## False positives
- The endpoint returns data already owned by the requesting account, but the identifier coincidentally matched the caller's own record.
- A shared or intentionally public resource where the identifier is not actually a boundary, so the same value is disclosed to everyone by design.
- A field only echoed from the request rather than a stored object fetched by that identifier — verify the returned body actually corresponds to the other principal's record.

## Stop conditions
- `scope_preflight` rejects the target or identifier scheme — stop immediately.
- Proving it would require a write, a mass fetch, accessing a third-party's data, or anything R3/R4 with no recorded approval — stop.
- Any step needs credentials you cannot obtain as your own out-of-band test accounts — do nothing until authorized.

## Example
A task API at `api.example.test/invoices/{id}` uses sequential integer ids. You create two accounts on `example.test`. Account A requests `GET /invoices/1007` (its own) and sees invoice 1007. Predict: as account B, requesting `GET /invoices/1007` will return account A's invoice if authorization is broken, or 403/404 if enforced. You send the one broker-mediated GET as account B and observe the body containing account A's invoice total. The single read-only response demonstrates cross-principal access and is recorded as evidence.