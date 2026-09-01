# Portability

`HarnessPaths` is the authoritative layout. User state resolves from `BUGHUNT_HOME` (then the configured path, then `${HOME}/.bughunt`); `BUGHUNT_PROGRAMS_DIR` and `BUGHUNT_CONFIG` override their specific locations. Source resolves from `BUGHUNT_PROJECT_ROOT`, repository/package discovery, then the installed module location.

Tracked runtime configuration uses `./harness`. `harness sync` regenerates runtime-owned files and relative skill links, and repairs only unambiguous zero-byte generated placeholders. Doctor scans canonical source/config for personal absolute paths. A deterministic test copies the project to a random path containing spaces, uses an alternate `BUGHUNT_HOME`, and runs init/sync/doctor.
