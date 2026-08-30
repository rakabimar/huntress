# Source execution security

Static source analysis is read-only. Registration accepts explicit local Git
repositories or HTTPS locators supplied by the human and materializes an inert,
commit-pinned archive. It does not run hooks, install packages, import project
modules, build containers, execute workflows, or run tests.

Never automatically run `npm install`, `pip install`, `make`, `cargo build`,
`go test`, Maven/Gradle, Docker builds, or project scripts. Controlled execution
uses fixed project-type templates in the source sandbox. Build-based CodeQL
database creation is ASK-gated and sandboxed; prebuilt databases and supported
no-build language databases avoid repository execution. Every mode is denied
access to host-home credentials, browser/Burp/AuthContext secrets, the network,
and other program workspaces.

File reads and searches are path-contained, size/result bounded, and redacted.
Secret scanning stores detector, type/rule, fingerprint, file/line, and triage
state—not raw values. Discovered credentials are never authenticated with absent
an explicit policy-approved validation plan.
