# Capability packs

The default router loads web/API skills plus at most two supporting skills.
Optional packs activate only when program scope, recon, or source context shows
the surface:

- `cloud-security`: application/cloud identity, policies, storage, signed URLs,
  metadata, serverless, and cross-account boundaries;
- `llm-ai-security`: tool authorization, RAG/memory isolation, indirect prompt
  injection with protected effects, and connector boundaries;
- `client-reverse`: routes, signing, flags, WebAssembly, and client/backend parity;
- `mobile-security`: APK/IPA static context, deep links, WebView, exported
  components, local secrets, and mobile API parity;
- `grpc-security`: reflection, metadata, method/stream authorization, REST parity;
- `fuzzing`: local parser harnesses, corpus, coverage, sanitizers, crash triage,
  deduplication, minimization, and root cause.

These packs are draft and explicitly gated. They do not authorize cloud red
teaming, device persistence, high-volume production fuzzing, or repository code
execution.
