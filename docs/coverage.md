# Observed surface coverage

Coverage counts only the surface the Harness has observed. States distinguish discovered, baselined, tested, hypothesis-exhausted, deferred, ROE/auth-blocked, and stale/changed surfaces. `harness coverage summary --program <slug>` reports counts by endpoint, parameter, AuthContext class, and skill family plus high-interest untested endpoints; it does not publish a vanity application percentage.
