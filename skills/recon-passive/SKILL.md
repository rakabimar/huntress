---
name: recon-passive
description: Use when mapping an in-scope target's public surface from registrars, TLS certificates, DNS, whois, and web archives to generate leads
maturity: draft
risk_class: R1
category: recon
cwe: [200]
---

# Passive Reconnaissance

## Purpose
Passive reconnaissance builds a map of an in-scope target's public footprint using only read-only, publicly available sources: domain registrars, TLS certificate transparency logs, DNS records, whois, and web archives. It crosses no authorization boundary and produces *leads*, not findings. A solid map is what later lets a hypothesis target the real weakness instead of shotgun-scanning.

## When to use
- A new program is active and you have a scope of domains/hosts but no idea of the attack surface yet.
- You want to enumerate subdomains, related assets, or historical infrastructure before touching any live endpoint.
- A TLS/CT log entry or DNS record hints at a host or technology worth investigating.
- You need third-party context (registrant, mail servers, prior versions) to shape a hypothesis.

## Process
1. Confirm each target domain passes `scope_preflight`. Record what is in scope before any lookup.
2. Write a falsifiable hypothesis with `create_hypothesis`, e.g. "If I check DNS/CT logs for <scope domain>, I will find additional hosts not listed in the brief."
3. Run the MINIMAL read-only experiment through `send_authorized_http_request` (or `scope_preflight`+`policy_preflight`-gated lookups). Never use raw `curl`/`nmap`/`sqlmap` for reconnaissance.
4. Feed each discovered host through `scope_preflight`; discard out-of-scope items without recording them as evidence.
5. Record the observation and result with `complete_research_test`. Persist artifact references with `create_evidence`.
6. Promote only *supported* hypotheses into new leads (hosts, technologies, historical versions). Stop before claiming a vulnerability.

## Evidence
- `observation` — a discovered host, DNS record, or certificate field, with source noted.
- `request_response` — the redacted response from a rate-limited archive or CT log query.
- `command_output` — hostname/whois-style output, captured only via authorized channels.
Always redact secrets and PII from stored previews.

## False positives
- A subdomain that resolves to a parked/squatted page is not an asset; confirm ownership before treating it as scope.
- A wildcard DNS record answering every name does not prove individual hosts exist — test a random nonce label.
- Registrant/name-server data pointing at a cloud provider is shared infrastructure, not a target-specific weakness.
- Historical archive content describes an old, patched state; it is context for a hypothesis, not current attack surface.

## Stop conditions
- `scope_preflight` rejects the target -> stop; do not test out-of-scope items.
- The action requires R3/R4 or approval and none is recorded -> stop.
- Proving a lead would require active, destructive, or high-rate probing -> stop.
- You cannot tell whether a lookup is authorized -> resolve to no.

## Example
For scope `example.test`, hypothesize that public sources expose more than the two documented hosts. Query read-only DNS (A/AAAA/CNAME/MX) and the certificate transparency log for `example.test`, plus a whois lookup for the registrant. The checks `supports` the hypothesis when they surface `mail.example.test` and `api.example.test`. Record each discovered name as a lead and every query as evidence, then stop at the lead stage — no probe against live hosts.

Track observed-surface coverage and bundle hash changes. Watch mode remains passive by default; new JavaScript endpoints and changed/stale high-interest surfaces may raise Leads but never Findings.
