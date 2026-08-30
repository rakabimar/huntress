# Program intake

Official linked policy documents are fetched one level only after official-origin validation. HTML, Markdown, plain text, JSON and text-extractable PDF are bounded, hashed and extracted without script or attachment execution. Provenance records the URL, retrieval metadata, raw hash, parser, page count where available and extracted-text hash. Unsupported or unparseable documents remain explicit ambiguities.

Program intake automates extraction and data entry. It never automates authorization.

For unresolved official prose only, normal intake can invoke a constrained
parser with `--llm-policy-parser claude`. The parser receives only policy text
and a strict schema with an empty tool surface. Its output is marked `PROPOSED`,
preserves source/parser/model/reason metadata, and still requires ambiguity
review plus human import approval. It cannot activate a program or authorize
testing.

The lifecycle is `FETCHING → IMPORTED_DRAFT → REVIEW_REQUIRED → APPROVED → VALIDATED`; activation remains a separate explicit human command. Failed fetches and parses are retained as `FETCH_FAILED` or `IMPORT_FAILED`. Refreshes with material changes become `CHANGE_REVIEW_REQUIRED`.

```bash
./harness program import --platform hackerone --handle acme --credential researcher-main
./harness program review --program acme --interactive
./harness program approve-import --program acme
./harness program activate --program acme
```

Raw source bodies, normalized data, field provenance, proposed YAML, review data, and semantic diffs are isolated under the program workspace at `intake/IMPORT-NNN/`. Request authorization headers are never stored there.

`import ≠ approval` and `approval ≠ activation`.

Structured source fields are preferred over prose. Unknown testing authorization is blocked. Submission eligibility and bounty eligibility are stored separately. Non-network assets remain visible in intake provenance but are not coerced into HTTP scope.

Local account secrets, autonomy limits, recon preferences, browser data, research state, Burp/Playwright overrides, evidence, and findings are not platform-managed and survive refresh.
