# Implementation notes

Implementation notes: support npm lock/package, requirements/poetry, go.mod/sum, Maven/Gradle, Gemfile.lock, composer.lock, and Cargo.lock. OSV or ecosystem audits create observations only. Avoid automatic package installation/audit scripts from the repository. Record advisory IDs and package paths, not massive scanner output.

Tool selection: git for provenance/history/diff; ripgrep for exact and sibling search; Semgrep for structural variants; CodeQL for justified cross-function dataflow; source semantic tools for bounded read/search/persistence; Broker only for the final authorized runtime hypothesis.
