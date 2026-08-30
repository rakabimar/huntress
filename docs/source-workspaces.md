# Source workspaces

Every program owns an isolated source plane:

```text
~/.bughunt/programs/<slug>/source/
  repos/       inert commit snapshots
  artifacts/   Git metadata/mirrors
  analysis/    compact context, redacted scan output, local rules
  indexes/     optional prebuilt analysis indexes/databases
```

`SourceRepository` records the official locator, requested ref, resolved commit,
retrieval time, relation, and snapshot provenance. Branches and tags are always
resolved to a full commit SHA. Updates retain `previous_commit`; observations
remain attached to the commit where they were made.

`SourceObservation`, `SourceAnalysisRun`, and `SourceRuntimeMapping` persist
small, versioned conclusions. They never cache a scanner result as a Finding.
The program-bound database and MCP session prevent one program from querying
another program's repository state.
