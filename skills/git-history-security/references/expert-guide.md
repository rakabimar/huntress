# Expert guide

## Evidence contract

Persist commit and parent, diff and blame provenance, the historical security
assumption, current affected symbol/callers, branch or release applicability,
and the condition that would show the behavior is fixed or unreachable.

Mental model: commit → changed security assumption → root cause → fix invariant → sibling/regression search. Attack surface includes removed validation, permission decorators, parser order, URL/path normalization, serializer type changes, secret handling, CI permissions, dependency upgrades, and release backports. Blame identifies context, not fault or exploitability.

Evidence must support each reachability/control claim. False positives are actively disproved before Lead promotion. Impact is research priority until normal validation; remediation should address the root control rather than the scanner signature.

Search commit subjects and diffs for authorization, validation, regression, bypass, CVE, hardening, temporary workaround, TODO/FIXME and deprecated insecure paths, but treat wording as prioritization only. For a candidate fix, inspect parent and child behavior, tests, branches/tags and whether the changed code ships. Blame answers when and with what nearby assumption a line appeared; it does not assign fault or prove the current line is unsafe.

Convert history into a RootCause only after identifying the violated invariant and exact behavior change. Then search current siblings and supported release branches. Reject commits that are refactors, test-only, defense-in-depth with no reachable unsafe state, or irrelevant to the mapped runtime. Use git for provenance, symbols for affected callers, differential review for blast radius and Semgrep/CodeQL only after the exact historical construct is understood.
