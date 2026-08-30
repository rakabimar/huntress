# Expert guide

## Mental model
Inbound: raw bytes → signature/key version → timestamp/replay → provider/account/tenant → event type/object → idempotent domain transition. Outbound: tenant-authorized destination → URL validation/SSRF controls → secret/signature → retries/rotation → data minimization.

## Attack surface
Signature over parsed versus raw body, algorithm/key ID, multiple active secrets, tolerance/replay store, duplicate/out-of-order delivery, event type confused with object state, provider account mismatch, test endpoints, callback ownership, redirects, and secret rotation.

## Methodology and decision tree
Use provider test fixtures or captured controlled events. Establish one valid baseline; change one signature/time/delivery/event/object/tenant/destination binding; verify authoritative state and duplicate behavior. Never spoof real providers or probe internal callback networks.
