# Evidence, false positives, impact, and remediation

Evidence includes handshake metadata, Origin/subprotocol/auth context, connection principal, exact minimal message and correlation ID, channel/object ownership, server reply/event, lifecycle state, and protected postcondition. False positives: public broadcasts, rejected subscriptions, stale client display, server echo, and non-browser clients where Origin is irrelevant.

Remediate at upgrade and every message/subscription/event boundary, bind channels to principal/tenant, revalidate on privilege/logout changes, use explicit Origin allowlists for ambient-cookie browser clients, validate schemas, and bound rates.
