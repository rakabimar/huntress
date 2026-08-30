# Expert guide

Build a local harness around the narrow parser/API, deterministic seed corpus, coverage signal, sanitizers where applicable, resource/time limits, crash capture, deduplication, minimization, and root-cause/attacker-reachability triage. A crash is an observation until reproducible, reachable, and security-relevant. Repository-controlled builds/harnesses may execute code and therefore require ASK plus an isolated sandbox; do not npm/pip/build/test automatically. Network fuzzing is distinct, policy-gated, low-volume, and never aimed at availability.

Tool choice follows the cheapest sufficient observation: source search/read before structural analysis, structural analysis before deep dataflow, and authorized Broker/browser/local sandbox only when the hypothesis requires it. Evidence and remediation address the root trust boundary; false positives are rejected before Lead promotion.
