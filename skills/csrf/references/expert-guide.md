# Expert guide: CSRF

## Mental model
CSRF requires ambient authority automatically sent by a browser, an attacker-creatable cross-site request, and a security-relevant state change accepted without binding to the intended site/user action. Analyze cookie SameSite/domain, request method/content type, token binding, Origin/Referer policy, CORS/preflight, and UI interaction.

## Attack surface and methodology
Prioritize account email/password/factor changes, login CSRF, linking, transfers, role/invite changes, API keys, webhook configuration, and destructive actions. Determine whether cross-site HTML forms, simple requests, navigation, or same-site sibling origins can send the exact request with credentials. Use a controlled attacker origin/browser and one test account. Verify authoritative state.

Decision tree: bearer token not automatically sent → usually no CSRF; SameSite/Origin/token blocks request → reject; request arrives but no state change → reject; ambient credential plus attacker-controlled cross-site request changes protected state → support. Missing token/header alone is insufficient.
