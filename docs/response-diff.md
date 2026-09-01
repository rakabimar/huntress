# Response differences

`ResponseComparator` compares status/class, redirects, important and cache headers, content type, body length/hash, Set-Cookie behavior, timing metadata, normalized token/edit similarity, JSON keys/types/values, array cardinality, and response clusters. JSON ignore paths are explicit; security-sensitive differences are not silently suppressed. Output is a `DifferentialResponse` observation and never decides that an authorization or other vulnerability exists.
