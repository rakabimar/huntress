# Authentication attack surface

Inventory login, registration, verification/resend, reset request/consume, magic link, MFA enroll/challenge/disable/recovery, remembered devices, fallback/legacy login, account linking/unlinking, federation callbacks, re-authentication, and step-up consumers.

High-value comparisons:

- reset token bound to an email but not the account/user ID after an identifier change;
- verification or magic link consumed from another transaction/browser/account;
- one channel enforces expiry/single-use while mobile/legacy endpoint does not;
- MFA recovery or factor removal authenticates less strongly than enrollment;
- remembered-device state survives password/factor change or crosses accounts;
- account linking uses mutable email rather than issuer+stable subject and lacks recent re-authentication;
- a sensitive action requests step-up but an alternate endpoint accepts the pre-step-up session.

Rate-limit/enumeration tests must be explicitly allowed and bounded. Prefer two controlled identities and stable paired observations over volume.
