# Source symbols and call confidence

Use `harness source symbols --program <slug> <repository-id> [--name SYMBOL]`. The index is designed for high-value call paths, not perfect compilation.

- `EXACT`: syntax-resolved definition (Python AST or the installed Tree-sitter language pack).
- `HIGH`: one likely same-language target or framework adapter result.
- `MEDIUM`: lexical candidate.
- `UNKNOWN`: ambiguous dynamic dispatch, inheritance, reflection or missing configuration.

Function contracts distinguish assumptions from guarantees. Callers may assume authentication or tenant context; only a visible/inherited executable control supports a guarantee. Review direct callees, framework interceptors and data-layer scopes before claiming missing authorization.

Tree-sitter covers structural symbols and local call syntax for JavaScript,
TypeScript, PHP, Java, Kotlin, Go and Ruby (with Rust/C/C++ available as
non-default capability languages). It does not make type-aware call resolution
`EXACT`; ambiguous references remain `HIGH` or `UNKNOWN`, and CodeQL is still
the optional escalation for justified interprocedural flow.
