# Finding deduplication

Versioned fingerprints use category/CWE, normalized host and endpoint shape, method, affected parameter, authorization boundary, root-cause signature, and impact category. Deterministic comparison returns `EXACT_DUPLICATE`, `LIKELY_DUPLICATE`, `RELATED_VARIANT`, or `DISTINCT` with a reason and score. Variants are surfaced to the validator and are not automatically killed.
