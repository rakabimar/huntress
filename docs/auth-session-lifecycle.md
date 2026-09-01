# Auth session lifecycle

Static bearer/cookie/header/browser AuthContexts remain supported. Optional `STATIC`, `HTTP_LOGIN`, `REFRESH_TOKEN`, `COOKIE_LOGIN`, `BEARER_LOGIN`, and `MANUAL_BROWSER` strategies add bounded login/refresh metadata. Login and refresh are target requests through the Broker and default to one attempt plus at most one expiry retry.

User/password/refresh references use `env:`, `keyring:`, or `file:`. Extracted access/cookie/refresh values are persisted only by the Broker into program-local protected secret files (0600 where supported); the DB stores timestamps, state, counts, and references, never values. Known expiry refreshes with a 60-second skew. MFA/CAPTCHA/device approval becomes `WAITING_HUMAN` and is never bypassed.
