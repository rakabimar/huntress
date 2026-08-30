# Implementation notes

Implementation notes: exact ripgrep finds definitions and siblings; callers/references establish lexical reach; Semgrep expresses local structural patterns; CodeQL is justified for cross-function/cross-file flow. Scanner output is ingested as SourceObservation with rule, file, line, commit, and confidence. Do not build CodeQL databases when that executes repository code without ASK/sandbox.

Tool selection: git for provenance/history/diff; ripgrep for exact and sibling search; Semgrep for structural variants; CodeQL for justified cross-function dataflow; source semantic tools for bounded read/search/persistence; Broker only for the final authorized runtime hypothesis.
