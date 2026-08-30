# File lifecycle attack surface

Validation: extension normalization/case/trailing characters, MIME, magic bytes, polyglot ambiguity, size/count/dimensions, filename encoding. Storage: user filenames versus generated keys, bucket/container policy, overwrite, tenant prefix, direct/signed upload conditions, temporary object promotion.

Processing: image/video libraries, metadata/EXIF, SVG/XML, PDF renderers, office converters, OCR, antivirus, archive extraction, asynchronous queues, and callback/URL resolution. Retrieval: Content-Type/Disposition/sniffing, same-origin versus isolated domain, inline rendering, range/CDN variants, authorization on original and transformed objects, public links, expiry/revocation, deletion.

Format-specific hypotheses must remain inert and bounded. SVG/HTML needs browser execution proof; XML needs parser/entity behavior; archives need a harmless marker outside intended subdirectory in a local/approved fixture; processor vulnerabilities need safe source-only/local validation, never production crash payloads.
