# Curated CodeQL hooks

These local queries complement the existing safe CodeQL database/execution hook. They are optional, run only against a program-bound database, and produce SourceObservations. A result is `LEVEL_3` only when the CodeQL run completed and confirmed interprocedural flow. The Harness does not download packs or create a database without the existing policy gate.
