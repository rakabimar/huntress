---
name: payment-logic
description: Use when inspecting checkout, cart, order, coupon, or payment flows for price tampering and business-logic abuse.
maturity: draft
risk_class: R2
category: business-logic
cwe: [841]
---

# Payment Logic Integrity

## Purpose
Payment/checkout integrity failures let the client dictate monetary values that the server should own — price, quantity, currency, discounts, or order ownership. The server trusts a client-supplied field or an unvalidated identifier, and a user pays less (or nothing) than intended or reads another customer's order. This is CWE-841 (improper enforcement of behavioral workflow), a high-value class because one minimally altered value can demonstrate a measurable financial boundary crossing without destructive action.

## When to use
- Endpoints or forms that carry `price`, `amount`, `total`, `subtotal`, `quantity`, `currency`, `discount`, or `coupon` fields in the request body.
- Checkout flows with client-side totals, promo-code stacking, or multiple quantity/currency mutations.
- Order detail, receipt, or invoice endpoints whose URLs contain sequential identifiers.
- Recurring/subscription or wallet/credit features where a negative or zero amount could invert the flow.

## Process
1. Enumerate the checkout surface: identify which fields travel from client to server versus which are recomputed server-side.
2. Write a falsifiable hypothesis with `create_hypothesis`, e.g. "If I submit `price=1` for the item as account A, then the server charges 1 rather than 100, crossing the authorization boundary between my input and the server's pricing."
3. Predict the observable for true (server persists or charges the tampered value) and what refutes it (server re-prices, rejects, or logs).
4. Run the MINIMAL experiment through `send_authorized_http_request` only — one request changing a single value, never raw curl/nmap/sqlmap and never bulk mutation.
5. Record the observation and result with `complete_research_test`; persist the redacted request/response as `create_evidence`.
6. Prefer the least-invasive proof: change the value by a visible but harmless margin, and stop before any completed purchase if the flow would bill a real party.

## Evidence
- `request_response` pairs showing the tampered field and the server's echoed price/order total — redact session tokens and any PII.
- `observation` records noting whether the server recomputed, rejected, or accepted the modified value.
- `command_output` free; anything observable comes from broker responses, not local tools.

## False positives
- The UI shows a recalculated total client-side but the server still charges the correct amount — verify the persisted order, not the rendered page.
- A 4xx or generic validation message on the endpoint — confirm the change never reached pricing logic before treating it as rejected baseline, not a defect.
- A header/field merely echoed in the response without affecting the stored order — echo alone is not integrity loss.
- Order ID predictability without authorization checks — confirm a second account can actually retrieve another's order before claiming IDOR.

## Stop conditions
- `scope_preflight(target)` rejects the endpoint or host — stop immediately.
- The proof would require R3/R4 action or completing a real charge and no approval is recorded — stop.
- Demonstrating the effect would corrupt, delete, or persistently alter another user's order — stop and record a non-mutating observation instead.
- Any step risks placing a real order or triggering a payment — halt and request human approval before proceeding.

## Example
On `https://store.example.test/checkout`, the POST body includes `{"items":[{"id":42,"price":0.01,"qty":1}]}` while the catalog price is 100. Hypothesis: the server persists client `price`. One broker request sets `price` to `0.01`; the response and order lookup show a total of `0.01` rather than 100, demonstrating that the server trusts the client-supplied amount. Stop before payment settles; document the request_response evidence with tokens redacted.