# Recon profiles

- `passive`: subfinder, assetfinder, and passive amass; no direct target traffic.
- `light`: passive, DNS, HTTP/TLS metadata, bounded anonymous crawl, Burp ingest.
- `standard`: light plus archives, Katana, JS/endpoint/parameter and technology enrichment.
- `deep`: standard plus low-impact Nuclei observations, targeted ffuf, and bounded port/service discovery.

Deep is never the default. Its R3 stages resolve to `ASK` unless an approved,
bounded program policy permits them. `DENY` is final. Tool failures produce a
`partial` run and do not erase successful observations from other sources.
An approved plan is bound to the same program/session, exact profile or stage,
explicit target set, request ceiling, concurrency, and duration; pass its ID
with `recon run --approval APP-NNN`. The approval is consumed once.

Freshness defaults are passive 24 hours, light 12 hours, standard 24 hours,
and deep 168 hours. Autonomous hunting escalates passive → light → standard →
deep only when no actionable Leads remain and every stage's policy gate allows
the next profile.

Override freshness, `lead_threshold`, or named deterministic
`interest_weights` in each program's `recon.yaml`. Unknown weights are ignored;
values are bounded to -100..100.
