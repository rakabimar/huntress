# Source sandbox

Normal source analysis never executes repository code. Semantic build, test, reproducer and fuzz actions are R3/ASK and run only after a human-approved, session-bound plan.

The current backend is rootless Bubblewrap. It creates new namespaces, disables
networking, mounts the pinned source as `/src-original`, and gives the process a
disposable writable `/work`, isolated `/out`, `HOME`, `TMPDIR`, and XDG cache.
It does not mount the host home, credentials, other programs, or Docker socket.
CPU, address-space, process, file-descriptor, wall-clock, and aggregate
work/out/tmp disk bounds are enforced. Commands come from fixed project
templates or one validated relative reproducer path; no shell string is exposed.

Plan safely:

```text
harness source sandbox --program acme SRC-001 --operation test --plan
```

Execution requires `--session` and then the returned human-approved `--approval`. Dependency downloads and arbitrary outbound network remain denied.
Offline dependencies may be supplied explicitly with
`harness source prepare-dependencies REPO --snapshot PATH -p PROGRAM`. The
Harness copies the human-prepared cache into the program workspace, rejects
symlinks and oversized snapshots, hashes every file, and executes no repository
scripts or downloader. Later sandboxes copy that cache into their isolated
HOME and remain network-off.

CodeQL database preparation is exposed as `source create-codeql-database` (and
the equivalent role-filtered MCP tool). `PREBUILT` is read-only/AUTO; supported
no-build languages run a fixed CodeQL template; build-required projects are
ASK-gated and always build inside this sandbox.
