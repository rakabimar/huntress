# Getting started

The maintained setup is split into [installation](installation.md) and the
[operational quickstart](quickstart.md). The short form is:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[full]'
npm install
./harness init
./harness sync
./harness doctor

./harness program create my-program --platform custom
# Configure the generated program workspace with real authorized scope/ROE.
./harness engagement validate --program my-program
./harness program activate --program my-program
./harness doctor --program my-program --deep
./harness hunt --program my-program
```

New program scope is deliberately empty, so activation fails until an actual
engagement is configured. Synthetic acceptance runs only in isolated temporary
workspaces during tests/deep doctor. Read [`AGENT_CORE.md`](../AGENT_CORE.md)
for the canonical operating contract.
