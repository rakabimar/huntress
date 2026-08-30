---
name: xss
description: Use when attacker-controlled data may execute in reflected, stored, DOM, client-template, framework, HTML, attribute, JavaScript, URL, or other browser interpretation contexts.
maturity: stable
risk_class: R2
category: injection
cwe: [79]
canonical: true
primary_specialist: client-side-specialist
related_skills: [postmessage, file-upload, csrf, content-security-policy]
primary_triggers: [reflection, DOM source and sink, stored rendering, unsafe HTML]
secondary_triggers: [sanitizer, CSP, Trusted Types, framework escape hatch]
negative_triggers: [encoded reflection, inert text, self-only unreachable sink]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Cross-Site Scripting

## Purpose
Prove an attacker-controlled value reaches a browser executable sink after context-specific transforms and defenses. Reflection is a source observation, not XSS.

## When to use
Use for reflected/stored/DOM/client-template flows and HTML text, quoted/unquoted attribute, URL, script-string/expression, template, SVG, or framework escape-hatch contexts. Analyze source, transforms, sink, encoding, sanitizer, CSP, Trusted Types, frame sandbox, and DOM lifecycle.

## Process
1. Read references/mental-model.md. Trace source → transforms/decoding → context → sink → browser lifecycle → security defenses.
2. Establish a harmless marker and identify the exact raw-response or DOM insertion context. Server and DOM XSS require different evidence planes.
3. Test one structural boundary character or safe DOM marker at a time. Choose a non-exfiltrating execution proof matched to the context; never start with a payload list.
4. For stored XSS, prove a controlled second-viewer context and persistence. For DOM XSS, capture the value reaching an executable sink. For frameworks, identify the explicit escape hatch or sanitizer bypass.
5. Evaluate CSP/Trusted Types as exploitability controls: a sink blocked in the tested deployment is not demonstrated execution. Support only observed attacker-controlled execution or a rigorously reachable equivalent allowed by program rules.

## Evidence
Record source, transformations, exact sink/context, encoding/sanitizer behavior, CSP/Trusted Types/frame policy, payload marker, execution observation/screenshot, affected viewer relationship, persistence, and minimal demonstrated capability. Do not read cookies or exfiltrate data.

## False positives
HTML-encoded reflection, DOM textContent, inert JSON, sanitized markup, a javascript URL requiring impossible interaction, browser-extension effects, self-XSS without a credible delivery boundary, and CSP-blocked inline execution with no demonstrated bypass.

## Stop conditions
Stop before victim targeting, cookie/token theft, data exfiltration, persistent payloads visible to real users, worm behavior, or R3/R4. Use synthetic viewers and inert DOM changes; ASK for controlled stored-viewer actions.

Read references/attack-surface.md for context and framework branches; compose postmessage or file-upload when the source enters through those features.
