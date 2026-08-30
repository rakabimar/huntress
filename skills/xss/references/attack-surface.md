# Context and sink attack surface

Sources: query/path/hash, form/profile/comment content, filenames/metadata, API/GraphQL fields, postMessage, local/session storage, WebSocket events, server headers/errors, uploaded SVG/HTML, and third-party integration data.

High-risk sinks/escape hatches: innerHTML/outerHTML/insertAdjacentHTML, document.write, srcdoc, unsafe eval/function/timer strings, framework raw-HTML directives, template compilation, unsafe URL assignments, DOM clobber-sensitive code, and sanitizer allowlists permitting active attributes/protocols.

Testing decision: locate harmless marker → determine raw response versus runtime DOM → identify exact boundary characters/transforms → choose one inert structural proof → observe execution via safe DOM state → assess deliverability/viewer/prerequisites. For stored input use controlled second account; for postMessage verify origin/source; for upload verify serving origin/headers.

Browser tooling is appropriate for DOM lifecycle and execution. Broker evidence remains necessary for stored/reflected request provenance. Never phone home or read sensitive browser state.
