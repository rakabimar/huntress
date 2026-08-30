# Readiness

Doctor preserves black-box readiness when optional whitebox tools are absent. `WHITEBOX_READY` requires the source schema, Git, ripgrep and the built-in AST index. Semgrep, CodeQL, OSV-Scanner, secret scanners, Tree-sitter packs and the sandbox are reported individually as optional warnings.

`MODEL_VERIFIED` and `WHITEBOX_MODEL_VERIFIED` are truthful acceptance states. They remain `NOT_RUN` until an actual configured model completes the corresponding local-only acceptance; deterministic pytest does not upgrade them.
