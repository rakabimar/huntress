# Implementation notes

Implementation notes: store rule ID, commit, file, line, match, generalization level, and triage. Validate model-generated Semgrep syntax and keep rules under program source/analysis/rules. CodeQL database creation may execute builds and therefore requires source-execution policy; prebuilt databases/no-build extraction are preferred.

Tool selection: git for provenance/history/diff; ripgrep for exact and sibling search; Semgrep for structural variants; CodeQL for justified cross-function dataflow; source semantic tools for bounded read/search/persistence; Broker only for the final authorized runtime hypothesis.
