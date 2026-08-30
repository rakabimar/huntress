# Implementation notes

Trace session creation, server-side lookup/cache, authentication middleware, rotation, revocation store, refresh transaction, and cookie serialization. In distributed systems compare revocation propagation and verifier caches without mistaking documented short convergence for permanent validity.

Cookie review is threat-model-specific: Secure protects transport, HttpOnly limits script reads but not authenticated actions, SameSite controls some cross-site sends, Domain broadens subdomain trust, and Path is not a hard security boundary against same-origin scripts.

Remediate with server-side revocation or short-lived tokens plus robust refresh-family control, atomic rotation, privilege-event reissue, explicit device/session ownership, bounded cache propagation, and regression tests for every invalidation event.
