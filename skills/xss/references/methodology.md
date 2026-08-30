# Context-first XSS methodology

Place a harmless marker, identify source and final raw-response/DOM context, then trace transforms, encoding, sanitizer, and browser defenses. Change one structural boundary character or use one context-matched inert execution marker. For DOM cases capture runtime source-to-sink; for stored cases use a controlled second viewer.

Support requires observed attacker-controlled execution or an allowed rigorously equivalent browser effect in the deployed CSP/Trusted Types/sandbox context. Literal/encoded reflection rejects XSS.
