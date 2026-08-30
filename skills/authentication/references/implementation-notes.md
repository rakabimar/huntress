# Implementation notes

Source review should locate where identity is normalized, proof artifacts are generated/hashed, transaction state is stored, factors are enrolled/verified, external IdP subjects map to local accounts, and sessions are issued. Compare all consumers of the same token family.

Common mistakes: selecting account by a client field after validating a token for another subject; checking token signature but not purpose/audience; deleting tokens after the side effect rather than atomically consuming them; using email as a cross-IdP primary key; treating a remembered-device cookie as a second factor; and step-up represented only in client state.

Remediate by binding purpose+subject+transaction+consumer, atomic single use, short expiry, explicit invalidation, stable federated identifiers, recent-auth requirements, and uniform enforcement across channels.
