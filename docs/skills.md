# Skill library

Skills encode *how* a specialist stance executes a specific technique. They live
in `skills/<slug>/SKILL.md` with a YAML frontmatter and a fixed body structure,
and are routed through `skills/manifest.yaml`.

## Anatomy

```yaml
---
name: open-redirect
description: …what it finds and when to use it…
maturity: draft          # draft | stable | verified
risk_class: R1           # R0–R4
category: injection      # core / injection / authnz / …
cwe: [CWE-601]
---
# Title

## Purpose
## When to use
## Process
## Evidence
## False positives
## Stop conditions
```

The six `##` sections are *required*. `maturity` and `risk_class` are
schema-validated (`VALID_MATURITY`, `VALID_RISK`).

## Categories (48 skills)

- **core (8)** — `observe`, `hypothesize`, `research-loop`, `attack`, `defend`,
  `triage`, `validate`, `report`
- **injection (8)** — sqli, nosqli, command-injection, xss, xxe, ssti,
  ldap-injection, header-injection
- **authnz (6)** — authn-bypass, jwt-misuse, oauth-misuse, idor,
  privilege-escalation, session-fixation
- **business-logic (5)** — business-logic, race-condition, mass-assignment,
  payment-logic, workflow-bypass
- **file (4)** — file-upload, path-traversal, lfi, unrestricted-download
- **web (3)** — csrf, ssrf, open-redirect
- **client-side (4)** — prototype-pollution, cors-misconfig, postmessage, websocket
- **infra (4)** — subdomain-takeover, request-smuggling, host-header, cache-poisoning
- **crypto-config (4)** — crypto-misuse, information-disclosure,
  insecure-deserialization, rate-limit-bypass
- **recon (2)** — recon-passive, api-enumeration

## Validation & evaluation

```bash
./harness skill list
./harness skill validate     # schema + required sections + fixture hosts + manifest coverage
./harness skill eval [slug]  # per-skill deterministic checks
```

Two invariants are enforced structurally (spec §81):

1. Every skill carries all six required sections and a valid maturity/risk class.
2. Every example URL in a skill body must target a **fixture host** —
   `localhost`/loopback or a reserved TLD (`.test`, `.invalid`, `.localhost`,
   `.example`). Real hosts are never used in skill examples.

The manifest router (`skills/manifest.yaml`) must reference every skill (and
vice-versa); `skill validate` flags orphans in either direction.