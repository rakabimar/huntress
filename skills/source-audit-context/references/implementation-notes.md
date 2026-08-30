# Implementation notes

Implementation notes: identify framework conventions without assuming they are used correctly. For Python, JS/TS, PHP, Java/Kotlin, Go, Ruby, C/C++, and Rust, record entrypoint patterns, middleware/policy conventions, ORM/raw-query boundaries, process/filesystem/HTTP/deserialization sinks, and build/plugin surfaces. SourceContext is versioned; refresh changed files and controls rather than rereading a massive repository.

Tool selection: git for provenance/history/diff; ripgrep for exact and sibling search; Semgrep for structural variants; CodeQL for justified cross-function dataflow; source semantic tools for bounded read/search/persistence; Broker only for the final authorized runtime hypothesis.
