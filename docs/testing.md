# Testing

The suite under `tests/` validates the deterministic core, state machine, skill
library, adapters, broker (against a loopback fixture), prompt-injection
backstop, and program isolation.

```bash
./.venv/bin/python -m pytest tests/ -q
./.venv/bin/python -m pytest tests/ -v

# Deterministic fresh-checkout gate (no optional workstation binaries/models)
./.venv/bin/python -m pytest -m "unit or integration_local" -ra

# Optional tools are separately classified and skip truthfully when absent
./.venv/bin/python -m pytest -m external_tool -ra
```

## What's covered

| Module | Coverage |
|---|---|
| `test_scope_engine.py` | exact/wildcard/exclude/URL-prefix/IP-CIDR matching |
| `test_policy_engine.py` | R0–R4, forbidden, ROE flags, manual approval, automation gate |
| `test_state_machine.py` | legal/illegal transitions; full finding/hypothesis/lead/approval/checkpoint round-trips |
| `test_cvss.py` | v3.1 + v4.0 scoring, severity bands, invalid vectors |
| `test_skill_registry.py` | ≥48 skills, structural validity, fixture-host detection |
| `test_adapters_sync.py` | render functions, session binding isolation, skill symlinks |
| `test_broker.py` | scope/policy short-circuits + a loopback happy path |
| `test_hooks.py` | dangerous/raw-network commands denied; benign + fixture-host allowed |
| `test_isolation.py` | state-DB cross-program binding rejected; registry separation |
| `test_context.py` | workspace creation, engagement loading, program-context wiring |
| `test_qa.py` | deterministic report QA pass/fail for each gate |

## Safety invariant (spec §95)

**No test performs real reconnaissance, scanning, exploitation, or HTTP against
a public/external target.** The only network I/O in the suite is a `HTTPServer`
bound to `127.0.0.1` on an ephemeral port, exercised through the broker's
approved-localhost path.

## Fixture hosts (spec §81)

All examples and fixtures use `example.test` / `localhost` / loopback only. The
skill-library validator enforces this on every skill, and the test-driven
`fixture_host` checks enforce it on fixtures.
