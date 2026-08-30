# Installation

Use a repository-local virtual environment; it is ignored by Git.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e '.[full]'
npm install
./harness init
./harness sync
pytest -q
./harness doctor
```

Python 3.11 or newer is required. Node/npm is required for the official
`@playwright/mcp` package. Claude Code is the primary autonomous runtime;
Codex and OpenCode adapters are generated without making either runtime a
prerequisite for Claude readiness.

Recon binaries are optional and installed separately. Run
`./harness recon install-guide` for upstream references. A practical standard
set is subfinder, assetfinder, amass, dnsx, ProjectDiscovery httpx, gau,
waybackurls, and katana. Nuclei, ffuf, naabu, and nmap are deep-profile tools.
The harness does not install privileged packages or download binaries.

Mutable program data is stored under `~/.bughunt`, not inside the repository.
Set `BUGHUNT_HOME` before `harness init` to select another root. Generated
runtime configuration contains absolute paths; rerun `./harness sync` after
moving the repository.
