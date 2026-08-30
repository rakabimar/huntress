# Session attack surface

Test events separately: initial login, MFA/step-up, role elevation/de-escalation, password change/reset, MFA change, logout current/all devices, device revocation, account disable, and refresh reuse.

Inspect:

- whether an attacker-chosen pre-login session survives authentication;
- whether privilege changes rotate identifiers and revoke the prior credential;
- current-session versus all-session logout semantics;
- old access/refresh behavior after password/MFA/account changes;
- concurrent device listings and revocation ownership;
- remember-me lifetime and factor strength;
- cookie Domain/Path collisions across subdomains, apps, staging/production, and duplicate names;
- SameSite and cross-site method/content-type behavior alongside CSRF tokens;
- refresh-family replay, descendant revocation, and multi-service caches.

Time tests need controlled clocks/samples; do not wait out long production timeouts or generate session floods.
