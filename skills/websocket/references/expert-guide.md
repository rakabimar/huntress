# Expert guide: WebSocket boundaries

## Mental model
Separate HTTP upgrade authentication, Origin/cross-site browser constraints, connection principal, per-message authorization, channel/subscription ownership, event-time authorization, reconnect/resume state, and protocol-specific framing.

## Attack surface and methodology
Inventory URL/query/subprotocol/cookie/token handshake inputs; connection init; subscribe/join; CRUD/action messages; broadcast rooms; binary/custom formats; reconnect and logout/revocation; GraphQL transport. Establish an authorized connection/message baseline, then change one principal, Origin, channel/object ID, action, or lifecycle state. Use isolated browser context for cross-site behavior and semantic WS tooling, never raw high-volume fuzzing.

Decision tree: upgrade succeeds but messages require authorization → not bypass; public channel → intended; unauthorized message accepted but no protected effect → observation; foreign data/action/event delivered → support. Origin absence matters only for browser ambient credentials. Flooding and production availability tests are DENY.
