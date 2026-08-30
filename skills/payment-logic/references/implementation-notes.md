# Implementation notes

Trace cart-to-intent creation, metadata bindings, callback/webhook handlers, event ordering, ledger writes, and entitlements. Common flaws: trusting return URL status, amount supplied by client, webhook event type without object/account binding, refund against stale amount, and idempotency stored after crediting.
