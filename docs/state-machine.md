# State machine

Research state lives in the per-program SQLite store (`state/hunt.db`) and is
mutated only through `HuntDB` methods / the MCP tools, never raw SQL. A directed
transition map (`bughunt_harness/state/constants.py`) enforces the canonical
research loop: agents cannot jump straight from observation to a validated
finding, evidence, or report.

## Entities & statuses

| Entity | Statuses |
|---|---|
| `lead` | `open` → `claimed` → {`open`, `closed`}; `closed` is terminal |
| `hypothesis` | `open` → `testing` → {`supported`, `rejected`, `inconclusive`, `candidate`}; `supported`/`candidate` → {`candidate`/`rejected`; `supported`/`rejected`}; `rejected` terminal |
| `research_test` | `planned` → `executed` (terminal); result ∈ {`supports`, `rejects`, `inconclusive`} |
| `finding` | `candidate` → `validation` → `validated` → `poc_ready` → `scored` → `report_ready` → `qa_passed` → `human_approved`, with `rejected`/`killed` reachable at most gates |
| `session` | `running` → `ended` |
| `approval` | `pending` → {`approved`, `rejected`, `expired`} |

The finding pipeline is the strict spine:

```
candidate → validation → validated → poc_ready → scored → report_ready
          → qa_passed → human_approved
```

You **cannot** go `candidate → validated` directly; the `validation` gate must
execute (the deterministic `harness finding validate` plus the adversarial
validator's disprove attempt).

## Enforcement

`validate_transition(entity, from, to)` raises `InvalidTransitionError` (exit
code 7) on any illegal transition. `HuntDB` methods call it before every
status mutation. Deliberately important consequences:

- A lead can only be **closed from `claimed`** (open → claimed → closed), so a
  lead must be claimed and worked before closure.
- A hypothesis must pass through `testing` before it can be `supported`.
- A finding can only reach `human_approved` via the full pipeline, and
  `human_approved` — the only submit-authorizing state — has **no** outgoing
  transitions (terminal).

## Public IDs

Every record gets a human-facing public id (e.g. `LEAD-003`, `FIND-007`,
`EVD-012`) derived from its row id. Agents cite these, not raw row ids.

Using the store via `HuntDB` (or the MCP entity tools) guarantees provenance and
transition legality; the `.gitignore`d `hunt.db` never leaves the program
workspace.