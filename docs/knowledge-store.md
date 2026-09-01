# Security knowledge store

The knowledge store uses SQLite FTS5 without embeddings. It ingests versioned MITRE CWE records, cached advisory observations (including OSV-shaped documents), and user-supplied public/owned report exports. Queries return concise titles/summaries/IDs. External knowledge informs methodology but never grants testing authorization. Private program URLs, source, findings, and credentials are not promoted globally without an explicit sanitized process.
