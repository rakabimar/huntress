# Session lifecycle model

Model a directed credential family rather than a single cookie:

`anonymous identifier → authenticated session → rotated elevated session → access tokens ↔ refresh family → revocation/expiry`

For every credential class record issuer, server state, client storage, Domain/Path/origin/environment scope, identity/device binding, idle and absolute expiry, rotation triggers, predecessor validity, explicit revocation, and descendant invalidation.

Rotation without predecessor invalidation can be fixation. Logout UI without server revocation is not logout. Refresh rotation must define what happens when an old member is reused. Privilege decreases must invalidate or re-evaluate capabilities, not only update the account record.
