# HackerOne import

Configure references once:

```bash
export HACKERONE_API_USERNAME='researcher-name'
export HACKERONE_API_TOKEN='...'
./harness platform credential add hackerone researcher-main \
  --username-ref env:HACKERONE_API_USERNAME \
  --token-ref env:HACKERONE_API_TOKEN
```

Then import with `./harness program import --platform hackerone --handle acme --credential researcher-main`.

The adapter reads only `GET /v1/hackers/programs/{handle}`, `GET /v1/hackers/programs/{handle}/structured_scopes` with JSON:API pagination, and `GET /v1/hackers/programs/{handle}/scope_exclusions`.

The program resource supplies policy and program metadata. Structured scope retains platform ID, asset type and identifier, submission eligibility, bounty eligibility, instruction, maximum severity, timestamps, reference, and CIA requirements when present. The current documented structured-scope rate is respected through the adapter limiter; `429`, transient `5xx`, and network failures receive bounded retries only.

Without credentials, public fallback is capability-limited and cannot authorize private data or silently claim that structured scope was fetched. Official references: <https://api.hackerone.com/hacker-resources/> and <https://api.hackerone.com/hacker-reference/>.
