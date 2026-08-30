# Program refresh and change safety

Use `./harness program refresh --program acme` and inspect `./harness program diff --program acme`.

Refresh creates a new isolated source snapshot and semantic draft. Identical semantics update currentness without asking for approval.

Material changes follow one rule: **restrict automatically; expand only after human approval**.

Restrictive changes include removed scope, lost submission eligibility, new exclusions, newly prohibited techniques, lower limits, and closed/paused platform state. A protective overlay immediately narrows the effective Scope/Policy engines. Closed or paused programs block new sessions immediately.

Permissive changes—new scope, removed exclusions, newly allowed techniques, or higher limits—remain outside effective authorization until review and exact-hash approval. During `CHANGE_REVIEW_REQUIRED`, a new hunt cannot silently start.

The default freshness policy is 24 hours with `refresh_before_hunt: true` under global `program_intake` configuration. A new runtime launch refreshes stale imported metadata. Temporary API errors never mean “program deleted.”
