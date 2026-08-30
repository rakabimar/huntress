# Implementation notes

Implementation notes: use bounded git log/blame/diff with exact commits. Before/after review asks what control was introduced or reordered and why. Check branches/releases/backports and runtime mapping; a fix on main may not apply to deployed release, and a historical vulnerable commit may be out of scope.

Tool selection: git for provenance/history/diff; ripgrep for exact and sibling search; Semgrep for structural variants; CodeQL for justified cross-function dataflow; source semantic tools for bounded read/search/persistence; Broker only for the final authorized runtime hypothesis.
