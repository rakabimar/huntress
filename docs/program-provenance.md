# Program provenance

Every authorization-sensitive normalized field references its official source, import revision, confidence, and compact excerpt hash where prose was involved.

```bash
./harness program provenance --program acme
./harness program provenance --program acme --scope api.example.com
```

The result distinguishes testing authorization, submission eligibility, and bounty eligibility. Raw policy paragraphs are not duplicated into every field; references point back to the isolated source artifact.

Human interpretations are appended as separate overrides with field, value, reason, human identity, timestamp, and source import. The imported source itself remains immutable. Refresh can therefore show whether an override still applies.
