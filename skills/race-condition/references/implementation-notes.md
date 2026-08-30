# Implementation notes

Look for read-check-write across transaction boundaries, locks taken on different keys, idempotency recorded after side effects, queue retries without business keys, optimistic version fields ignored, and uniqueness enforced only in application code. Payment/provider callbacks require idempotency across delivery IDs and business operation IDs. Use a two-worker local fixture for source-only reproduction; production concurrency remains broker/policy bounded.
