# Implementation notes

Trace request parser, validation helper, object key builder, storage SDK policy, queue/job, processor invocation, derivative key creation, and download controller/CDN. Compare every upload path (web, mobile, admin, direct, import) and every representation (original, preview, thumbnail, converted PDF).

Framework helpers may validate only extension/MIME and may trust client metadata. Cloud signed policies need exact key prefix, content constraints, expiry, method, and post-upload finalization. WordPress review should cover upload handlers, AJAX/admin-post/REST routes, `wp_handle_upload`, MIME filters, attachment capabilities, and path construction; nonce still is not authorization.

Remediate with centralized byte-based allowlisting, generated opaque keys, non-executable isolated serving origins, explicit download headers, sandboxed/up-to-date processors, archive path containment, least-privilege storage policy, and owner checks on all variants/lifecycle actions.
