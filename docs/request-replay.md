# Request replay

`RequestTemplate` reconstructs a secret-free request from a broker `RequestRecord` and its request/response evidence. `RequestMutation` changes one query, explicit path segment, header, JSON path, form field, or raw body location. Cookie and credential headers can only change through AuthContext/session mechanisms.

Replay always re-enters the Broker, so current scope, ROE, policy, approval bounds, AuthContext, rate/concurrency limits, and budgets are re-evaluated. Records persist parent/root IDs, replay depth, and a mutation summary. Replay depth is capped at 12.
