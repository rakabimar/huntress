# Implementation notes

Framework middleware must cover custom APIs, GraphQL mutations, multipart uploads, WebSocket upgrade where cookies authenticate, and legacy/admin routes. Reverse proxies must preserve Origin/Host semantics. WordPress nonces are CSRF controls with lifecycle limits, not authorization; pair them with capability checks.
