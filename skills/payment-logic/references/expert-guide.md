# Expert guide: payment integrity

## Mental model
Separate merchant order/cart, payment intent/authorization/capture, provider event, ledger, entitlement/inventory, refund, and reconciliation. Define invariants for amount, currency, recipient, order identity, quantity, single capture/refund, and correspondence between provider and application state.

## Attack surface and methodology
Review server-side price calculation, line-item identity/quantity, currency/tax/shipping, coupons/credits/gift cards, payment intent reuse, capture timing, provider return URLs, signed webhooks, refund/partial refund, cancellation, subscription/seat entitlement, and retry/idempotency. Use provider sandbox and minimal value only when program policy explicitly supports it. Change one value/state and verify provider plus internal ledger—not just UI/order response.

Decision tree: client value ignored/recomputed → reject; sandbox success without entitlement/ledger effect → observation; one provider transaction and one entitlement despite retries → correct; value/state divergence or duplicate credit/capture/refund → support. Financial mutation is usually ASK; real-money loss, chargeback, or third-party orders are DENY.
