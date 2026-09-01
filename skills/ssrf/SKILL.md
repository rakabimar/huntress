---
name: ssrf
description: Use when attacker input may influence a server-side URL fetch through parsing, normalization, allow/deny logic, DNS, redirects, proxies, webhooks, importers, previews, or document/media processors.
maturity: stable
risk_class: R2
category: web
cwe: [918]
canonical: true
primary_specialist: business-logic-specialist
related_skills: [webhook-security, file-upload, open-redirect, cloud-security]
primary_triggers: [server fetch, URL input, webhook destination, import by URL]
secondary_triggers: [PDF/image processor, redirect, DNS, metadata, blind callback]
negative_triggers: [browser-only fetch, plain redirect, fixed-enum destination]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# Server-Side Request Forgery

## Purpose
Determine whether attacker input controls a server-originated network request after every parser, normalization, validation, DNS, redirect, and client step. Prove the least network capability necessary; do not map internal infrastructure.

## When to use
Use for URL import, webhook configuration/test, fetch/proxy/preview, RSS, PDF/HTML renderers, image/media processors, callbacks, and source paths where tainted input reaches an HTTP client. Do not activate for client-side fetches, ordinary redirects, or destinations chosen from a fixed server enum.

## Process
1. Read references/mental-model.md. Model attacker input → parser → canonical URL → allow/deny logic → DNS → network client/proxy → redirect policy → destination.
2. Establish whether the server—not the browser, resolver, monitoring system, or client—makes the request using a unique marker at an authorized fixture/OOB endpoint.
3. Infer the applicable bypass class from implementation signals: parser disagreement, hostname/IP normalization, userinfo, scheme, IPv4/IPv6 representation, redirect revalidation, or DNS-time checks. Do not spray encodings.
4. Change one component and predict both the callback/response and the refuting observation. Follow redirects only when policy allows and validation behavior is the hypothesis.
5. After server fetch is proven, demonstrate only the minimum protected network effect authorized by ROE—prefer a local/internal fixture over real metadata or services.

## Evidence
Persist input and canonical interpretation, validation decision if known, unique callback token metadata, source/timing correlation, redirect/DNS chain, response behavior, and exact demonstrated destination capability. Redact internal banners, secrets, and metadata credentials.

## False positives
Browser fetch, DNS-only resolution, security scanner preview, asynchronous unrelated callback, open redirect, allowlisted fixed destination, URL accepted but never fetched, and a callback with no unique attribution.

## Stop conditions
Stop before internal scanning, cloud metadata credentials, arbitrary protocols, port enumeration, repeated OOB traffic, or targets outside Scope/ROE. ASK for sensitive internal/metadata validation; DENY destructive or availability effects.

Read references/attack-surface.md for parser and redirect decision trees and framework client behavior; use cloud-security only after cloud context is evidenced.

## Tool selection
Use source search/AST evidence to narrow parser behavior first. Use
`policy_preflight` and the request broker for one unique callback or local
fixture request. Do not use generic scanners or broad internal probing.

Prefer in-band proof. For a genuinely blind case, create one OAST probe bound to the current hypothesis/test, send one minimal Broker request, link its RequestRecord, then poll for exact correlation. Do not use OAST when an in-band discriminator exists.
