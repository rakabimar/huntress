# Program review and approval

```bash
./harness program review --program acme
./harness program review --program acme --interactive
./harness program ambiguities --program acme
./harness program ambiguity resolve --program acme AMB-001 --value 'true'
```

Related questions are grouped. Permission for low-traffic automated tooling with no numeric rate produces one conservative local-policy decision rather than separate rate, concurrency, crawl, and scanner questions.

Ambiguities are `INFO`, `WARNING`, or `CRITICAL`. Critical authorization uncertainty blocks approval. Some official states, such as a closed program or missing network scope, require a refreshed official source and cannot be overridden.

Final approval is CLI/human-only: `./harness program approve-import --program acme --approved-by "$USER"`. Confirmation defaults to no. Approval records exact normalized draft, canonical program, scope, and ROE hashes. A later edit invalidates activation. Approval promotes platform-managed data, preserves local-managed settings, and runs the existing engagement validator. It does not activate or hunt.
