# Expert guide

## Mental model
Model authenticated request/response + cacheability + cache key + cache/origin path normalization + extension/static rules + cookie/authorization variance + later unauthenticated/other-user request.

## Attack surface
Path suffixes/extensions, semicolon/matrix params, encoded delimiters, path-info, trailing segments, case/slashes, rewrite rules, static prefixes, CDN ignore-query rules, Set-Cookie/authenticated caching, Vary, and framework route normalization.

## Methodology and decision tree
Use only a synthetic private object and unique cache-buster. Establish authenticated dynamic baseline and ordinary unauthenticated denial. Add one source-informed static-looking path mutation, verify shared cache storage, then fetch the identical cache key without credentials/other controlled principal.
