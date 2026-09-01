# OAST / out-of-band interactions

OAST is an evidence precursor for blind behavior, not a vulnerability verdict. The Harness supports the official `interactsh-client` (public or `--server` self-hosted), a narrow configured provider adapter, and a synthetic local provider used only by tests. The installed Burp MCP exposes history/Organizer tools but no Collaborator operations, so doctor reports `BURP_COLLABORATOR_UNAVAILABLE`.

Third-party providers observe callback traffic. Correlation labels are random and never contain target, account, email, or credential data. Creating a third-party session requires the current program policy and a bounded human approval; embedding a callback in a target request separately uses `oob_test` through the Broker. Each probe binds one hypothesis and one research test, and evidence is created only after the exact target request is linked. Polling is bounded to 300 seconds with backoff.

Check locally with `harness oast providers --program <slug>`. An optional real connectivity check is explicit and must involve only a harness-controlled callback: `harness acceptance oast-smoke --provider interactsh` (when configured). Normal tests never contact a provider.
