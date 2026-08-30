# OAuth/OIDC transaction methodology

Diagram actors and the exact flow. Capture one controlled successful transaction and a binding ledger. Use two synthetic accounts, browsers, clients, or IdPs only where the hypothesis requires them. Change one binding—state, nonce, browser session, redirect, verifier, code recipient, issuer, token type/audience, or local-account link—and observe the completed authorization/account outcome.

Do not report missing parameters in isolation. A deviation supports a candidate only when an attacker-controlled transaction gains a usable code/token, logs into the wrong account, or creates an unauthorized identity link.
