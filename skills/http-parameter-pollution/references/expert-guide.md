# Expert guide

## Mental model
Model raw request → proxy/WAF/cache parse/normalize → framework parser → validation/auth/signature → application → downstream service. Record first/last/array/join/reject behavior for the exact parameter location.

## Attack surface
Duplicate query/form keys, duplicate headers, comma folding, arrays/brackets, JSON duplicates, percent/double decoding, case, separators, empty values, Unicode, method/content-type parsers, signature canonicalization, cache keys, and backend forwarding.

## Methodology and decision tree
Identify two relevant parsers and one protected field. Establish single-value controls, then one duplicate/encoding variant with two distinct harmless values. Observe which value each boundary uses through safe postcondition/source evidence; do not fuzz combinations.
