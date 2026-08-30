# Access-control attack surface

Map admin/support routes; HTTP method alternatives; legacy/mobile API versions; bulk/import/export functions; organization/workspace role inheritance; invite-selected roles; temporary grants; service accounts; support impersonation; ownership transfer; and privilege revocation.

High-signal discrepancies:

- nine routes use a role/permission middleware while a sibling route or alternate method does not;
- a client feature flag is trusted without a server entitlement check;
- a collection action enforces role while bulk or background job submission/result does not;
- an invitee may alter a role, accept after downgrade/revocation, or carry a role across tenant boundaries;
- impersonation starts with approval but privileged actions do not retain audit/actor restrictions;
- permission removal updates UI/state but old tokens, sessions, jobs, or cached policy decisions remain effective.

Use a single lower-role replay of the known higher-role baseline. Avoid endpoint guessing or privileged mutations whose effect cannot be contained to test fixtures.
