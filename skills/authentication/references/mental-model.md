# Identity-binding model

Every authentication path should preserve this chain:

`claimed identity → proof channel/factor → one transaction → intended account → authenticated session`

For each artifact record purpose, subject, transaction/browser binding, issuer, audience/consumer, expiry, single-use state, and invalidation events. Do not record the artifact value.

State machines matter:

- registration: unregistered → pending proof → verified → active;
- reset: requested → challenge issued → challenge consumed/expired → credential changed → prior sessions handled;
- MFA: primary authenticated → challenge pending → factor verified → step-up granted;
- linking: authenticated local account + re-authentication → external subject verified → unique link established.

Ask whether another account, channel, browser, endpoint, or stale state can consume the artifact. A response difference matters only if it reveals an attacker-useful identity oracle or weakens a protected transition.
