# Implementation notes

Implementation notes: Gitleaks/TruffleHog/NoseyParker must run redacted and return fingerprint/type/location only. Do not store raw report fields such as Secret or Match. Test/example markers, localhost endpoints, dead values, documentation, and synthetic formats are strong false-positive signals. Credential validation is policy-gated and normally ASK.

Tool selection: git for provenance/history/diff; ripgrep for exact and sibling search; Semgrep for structural variants; CodeQL for justified cross-function dataflow; source semantic tools for bounded read/search/persistence; Broker only for the final authorized runtime hypothesis.
