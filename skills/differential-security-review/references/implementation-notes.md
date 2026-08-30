# Implementation notes

Implementation notes: use source update previous_commit, bounded diff, route/control indexes, and changed-file priority. A source observation at head must not inherit a runtime mapping pinned to base. For compiled projects, do not execute builds to understand a diff unless policy ASK is approved and sandboxed.

Tool selection: git for provenance/history/diff; ripgrep for exact and sibling search; Semgrep for structural variants; CodeQL for justified cross-function dataflow; source semantic tools for bounded read/search/persistence; Broker only for the final authorized runtime hypothesis.
