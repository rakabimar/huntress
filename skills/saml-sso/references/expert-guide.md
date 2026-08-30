# Expert guide

## Mental model
Actors are user agent, Service Provider, and Identity Provider. Bind response/assertion signatures and reference coverage, trusted certificate/issuer, audience, recipient/destination, request ID/InResponseTo, time/one-time use, subject/NameID, attributes, RelayState, and issuer+subject to local account.

## Attack surface
Review SP-initiated and IdP-initiated flows, multiple IdPs/tenants, certificate rollover, encrypted assertions, response versus assertion signatures, wrapping/reference selection, replay caches, ACS endpoints, RelayState, attribute/role mapping, and account linking.

## Methodology and decision tree
Capture a controlled valid flow; map signed elements and bindings; change one subject/issuer/audience/recipient/request/replay/linking dimension using controlled IdP/accounts. Support only wrong-account authentication or protected role/session, not XML deviation.
