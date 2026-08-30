# Domain abuse questions

Checkout/inventory: can price, currency, quantity, shipping, tax, item identity, or stock change after quote/approval? Does the server recompute? Wallet/credits/gift cards: can value be replayed, transferred across tenant/account, spent before settlement, or refunded twice? Coupons: who/what is eligibility bound to and when is usage atomically consumed?

Subscriptions: can trial, plan, seat count, grace period, cancellation, renewal, or entitlement state diverge from provider state? Invites/roles: can role/email/tenant change after issue, acceptance occur after revoke/expiry, or one representation be replayed? Approvals/refunds/returns: can the requester approve, value change after approval, alternate endpoint skip checks, or stale authorization be reused? Quotas: are reservations, completion, failure, cancellation, and retries reconciled?

Favor feature documents, runtime transitions, and source invariants over generic price-zero mutations. One actor/state/value change per test.
