# Authorization attack surface

Inventory reads, creates, updates, deletes, actions, exports, and result retrieval separately. High-signal inconsistencies include:

- a parent route checks tenant but the nested loader resolves a globally unique child without parent scoping;
- batch endpoints validate the container but not every ID, or omit unauthorized items while exposing counts/errors;
- search filters are authorized at query time but export/download rehydrates objects without the same predicate;
- an async job creator is authorized but job status, output, retry, cancel, or artifact URL is keyed only by job ID;
- PATCH permits server-controlled owner, tenant, role, status, approval, price, or visibility fields;
- older/mobile endpoints or GraphQL resolvers call a service without the policy wrapper used by the web REST route;
- authorization changes after archive, transfer, deletion, restore, invite acceptance, or role revocation;
- derived IDs, slugs, filenames, signed URLs, and server-generated references reach the same private object through another loader.

Whitebox: enumerate sensitive entry points and compare sibling control invocation. Trace route → middleware/decorator → object load → policy → persistence. A missing visible helper is a SourceObservation until centralized service enforcement is disproved. WordPress notes: `permission_callback` and capability checks authorize; a nonce only addresses request intent/replay and is not authorization.

Choose tools economically: Burp/recon inventory for principal/endpoint candidates; source search for exact policy helper siblings; Semgrep for structural variants; Broker for one same-object differential; Playwright only for state that cannot be safely reproduced at HTTP level.
