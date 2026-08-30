# XSS source-to-sink model

Trace `source → transforms/decoders → output context → DOM/browser parser → sink → execution policy`. The same string is safe or unsafe depending on its final context.

Contexts require different reasoning: HTML text; quoted/unquoted attribute; URL-bearing attribute; JavaScript string/template/expression; CSS-adjacent URL behavior; DOM insertion; client-template/framework escape hatch; SVG/XML; sandboxed or isolated document. Encoding must match the final context and occur after the last transform.

Stored versus reflected describes persistence/delivery; DOM describes client-side dataflow. A case can be stored DOM XSS. Framework auto-escaping protects template text but not explicit raw HTML APIs, unsafe URL handling, DOM sinks, third-party components, or sanitizer configuration.

Execution controls matter: CSP source lists/nonces/hashes/strict-dynamic, Trusted Types policy enforcement, sandbox, isolated origin, and browser lifecycle. Do not claim execution when the tested deployment blocks the path.
