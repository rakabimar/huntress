# Expert guide: cache poisoning

## Mental model
A shared cache stores an origin representation under a cache key. Poisoning requires attacker-controlled input that affects the stored response but is absent or normalized differently in the key, followed by an innocent request receiving that representation. Model cache layers, key dimensions, Vary, normalization, cacheability, TTL, and purge.

## Attack surface and methodology
Inspect Host/forwarded headers, unkeyed query parameters, path normalization, content negotiation, method overrides, cookies, origin routing, redirect/asset generation, error caching, and multi-CDN layers. Use a unique cache-buster and harmless marker, first prove cacheability/hit, then one influence, then a clean request without the influence. Avoid shared popular URLs.

Decision tree: reflection not cached → reject; input included in key → separate variant, reject poisoning; private/per-user cache only → no cross-user impact; clean request receives marker from shared hit → support. Cache-deception concerns private response cached under attacker-shaped path and is separate.
