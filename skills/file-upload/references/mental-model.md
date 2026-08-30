# File lifecycle and interpretation model

Track one file through: selection → multipart/direct-upload request → validation → naming/key generation → storage → processors/transforms → metadata → retrieval headers/rendering → sharing → deletion. Each stage may use different bytes, names, principals, and parsers.

Security invariants include:

- validated bytes are the bytes processed and served;
- storage keys cannot escape/overwrite another object and are not attacker-controlled paths;
- active formats never gain executable same-origin context unless explicitly trusted;
- processors are isolated, bounded, and safely configured;
- archive members remain under the extraction root;
- retrieval, signed URLs, variants/thumbnails, and deletion preserve owner/tenant/visibility;
- temporary/direct-upload objects cannot bypass finalize-time controls.

Declared MIME, filename extension, and magic bytes are three different signals. Acceptance is not impact; identify the later interpreter or protected object boundary.
