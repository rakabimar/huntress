# Implementation notes

React escapes JSX values but `dangerouslySetInnerHTML`, unsafe URL props, refs, and third-party renderers need review. Vue `v-html`, Angular trust-bypass APIs, Svelte `{@html}`, server template safe/raw filters, Markdown/render pipelines, and rich-text sanitizers are explicit trust boundaries. Next.js adds server/client serialization and route rendering contexts.

Trace source and sink across modules; search exact dangerous sink first, then callers, then the transform chain. A sink with constant/trusted content is not vulnerable. Sanitizer effectiveness depends on version, configuration, post-sanitization mutation, browser namespace/parser behavior, and final context.

Remediate with context-specific output encoding, safe DOM APIs, elimination of raw-HTML/eval paths, maintained allowlist sanitization at the final transform, validated URLs, strict CSP as defense-in-depth, Trusted Types for DOM sinks, and regression tests using the exact source/context.
