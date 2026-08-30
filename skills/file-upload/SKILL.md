---
name: file-upload
description: Use for the complete file lifecycle—selection, multipart/direct upload, validation, naming, storage, processing, transformation, metadata, retrieval, rendering, sharing, overwrite, archive extraction, and deletion.
maturity: stable
risk_class: R2
category: file
cwe: [22, 434, 436, 646]
canonical: true
primary_specialist: client-side-specialist
related_skills: [path-traversal, xss, xxe, ssrf, api-authorization]
primary_triggers: [multipart upload, direct upload, signed upload URL, attachment]
secondary_triggers: [image processor, archive, SVG, PDF, metadata, storage bucket]
negative_triggers: [file accepted but safely stored and served]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# File Upload

## Purpose
Determine whether attacker-controlled bytes cross an interpretation, storage, path, ownership, or retrieval boundary anywhere in the file lifecycle. Upload acceptance alone is not a vulnerability.

## When to use
Use for multipart and direct-to-storage uploads, signed URLs, avatars/attachments/imports, image/document/media processing, metadata extraction, archives, SVG/HTML/XML/PDF/office formats, public/private sharing, overwrite, and deletion.

## Process
1. Read references/mental-model.md. Draw the lifecycle: client selection → request/signing → server validation → storage key/bucket → processor/transformer → metadata → retrieval/rendering → sharing/deletion.
2. Identify each interpreter and security invariant: allowed bytes/type, generated path, non-executable serving context, private ownership, safe parser, isolated processor, archive containment.
3. Establish a benign synthetic baseline. Change one dimension: declared MIME, extension, magic bytes, filename/path, metadata, archive member, document active content, storage/retrieval identity, or processor-triggering content.
4. Verify the dangerous postcondition: browser execution, server interpretation, out-of-root write, overwrite, unsafe parser effect, unauthorized retrieval, public exposure, or cross-tenant control. A 200 upload response is insufficient.
5. Prefer inert markers and local fixtures. Separate ingestion, processing, and retrieval into distinct tests when asynchronous.

## Evidence
Record a hash/minimal description of test bytes, filename and declared/detected type, upload/storage/retrieval identifiers, processor state, ownership/visibility, and the exact dangerous interpretation or protected postcondition. Do not store malware, secrets, or unnecessary document contents.

## False positives
Accepted files renamed and served as attachment, SVG sanitized or isolated, public upload by design, signed URLs scoped correctly, parser errors without effect, metadata stripped, archive rejected/contained, and private object IDs that remain authorized.

## Stop conditions
Stop before executable malware, production parser crashes, large/decompression bombs, overwriting real files, active content sent to users, or internal/OOB processing outside ROE. ASK for one controlled mutation where policy requires; DENY destructive/DoS formats.

Read references/attack-surface.md for file-format and lifecycle branches; compose api-authorization for retrieval ownership, SSRF for URL imports, XSS for browser rendering, and path-traversal for storage/extraction paths.
