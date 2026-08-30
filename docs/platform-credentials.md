# Platform credentials

Platform credential definitions store references, never secret values:

```bash
./harness platform credential add hackerone researcher-main \
  --username-ref env:HACKERONE_API_USERNAME \
  --token-ref env:HACKERONE_API_TOKEN
./harness platform credential list
./harness platform status
```

Supported reference schemes are `env:`, `keyring:`, and `file:`. Listing reports only whether references are configured/resolvable and always renders values as `[REDACTED]`.

The importer does not inspect browser cookies, browser password stores, or personal profiles. API/session access must be intentionally configured. Credential definitions may be reused, while fetched private program data remains inside its one program workspace.
