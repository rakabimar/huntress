# AuthContexts

Accounts expose only identity metadata to the agent. Credential values remain
inside the broker. Initial types are `cookie`, `bearer`, `header_bundle`, and
`browser_session`.

```yaml
accounts:
  - id: account_a
    role: regular_user
    enabled: true
    auth:
      type: cookie
      cookie_ref:
        env: TARGET_ACCOUNT_A_COOKIE
  - id: account_b
    role: regular_user
    enabled: true
    auth:
      type: bearer
      bearer_ref: env:TARGET_ACCOUNT_B_TOKEN
```

References may use `env:`, `keyring:`, or a protected per-program `file:`.
Check availability without revealing refs or values:

```bash
./harness auth list --program acme
```

The broker resolves `auth_context=account_b`, injects the appropriate header,
and persists only the context ID and role. Paired baseline/mutation artifacts
support BOLA/IDOR, role, and tenant-boundary tests. Approval identity includes
AuthContext, so approval for Account A never authorizes Account B.

