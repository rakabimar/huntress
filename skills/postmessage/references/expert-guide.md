# Expert guide: cross-context messaging

## Mental model
For senders, bind message data to a specific targetOrigin and intended window. For receivers, validate event.origin exactly, event.source identity, message schema/type, transaction correlation, and authorization before any sink/action. Origin and source solve different problems.

## Attack surface and methodology
Inventory postMessage senders/listeners in iframes, popups, OAuth/payment widgets, embedded admin tools, workers, and token/data handoffs. Trace each message field to DOM sinks, storage, navigation, authentication, API calls, or privileged actions. Build a controlled parent/child/opener relationship from an authorized origin and deliver one inert message.

Decision tree: wildcard sender but only nonsensitive public data → observation; receiver origin check is exact and source bound → reject; message accepted but inert → no security effect; attacker origin drives protected action/data/executable sink → support. Regex/suffix allowlists need label-boundary analysis.
