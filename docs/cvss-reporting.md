# CVSS, PoC, and reporting

Only an independently validated finding enters the output pipeline:

```text
validated → PoC QA → poc_ready → metric reasoning → deterministic CVSS
→ scored → report → report QA → qa_passed → stop for human review
```

PoC QA requires prerequisites, account context, baseline, one controlled
change, reproducible steps, observed behavior, demonstrated impact, cleanup,
linked evidence, minimal impact, and no unnecessary victim data.

CVSS reasoning stores each metric's value, evidence-backed rationale,
references, and uncertainty before the maintained calculator receives the
vector. A vulnerability class never implies a score by itself.

Report QA requires a clear title, affected asset, weakness/CWE, prerequisites,
steps, PoC, expected/actual results, linked evidence, supported impact,
consistent CVSS, remediation, program eligibility, and no secrets/PII. The
harness never submits to a bounty platform.

