# Evidence, false positives, impact, and remediation

Evidence requires sandbox/test identifiers, quoted/order/provider/ledger amounts and currencies, item/recipient binding, idempotency keys by fingerprint, webhook event IDs, before/after entitlement, and reconciliation state. False positives include display rounding, pending authorization, test-provider artifacts, intended discounts, and duplicate UI messages with one ledger event.

Remediate by server-owned pricing, immutable amount/order bindings, provider-side verification, signed/replay-safe webhooks, atomic ledgers, business-key idempotency, and reconciliation tests.
