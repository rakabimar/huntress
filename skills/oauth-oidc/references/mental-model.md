# OAuth/OIDC actors and bindings

Actors: resource owner, user agent, client, authorization server, resource server, and—when distinct—identity provider. Do not merge them in reasoning.

Required bindings depend on the flow:

| artifact | must be bound to |
|---|---|
| state | initiating browser/client transaction |
| nonce | OIDC authentication transaction and ID token |
| authorization code | client, redirect URI, short lifetime, single use |
| code verifier | challenge, client transaction |
| issuer | client configuration and returned authorization response |
| access token | intended resource/audience and scopes |
| ID token | client/audience, issuer, nonce, authentication identity |
| federated identity | issuer + stable subject → one local account |

Email is generally mutable and non-unique across issuers; linking on email alone is unsafe unless the trust and verification rules explicitly justify it.
