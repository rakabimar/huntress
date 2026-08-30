---
name: sql-injection
description: Use when attacker input may alter relational query structure through raw SQL, query builders, ORM escape hatches, identifiers, dynamic sorting/filtering, stored procedures, JSON queries, or second-order use.
maturity: stable
risk_class: R2
category: injection
cwe: [89]
canonical: true
primary_specialist: business-logic-specialist
related_skills: [nosqli, source-dataflow-analysis]
primary_triggers: [SQL error, raw query, dynamic filter, sort identifier]
secondary_triggers: [ORM raw clause, stored procedure, JSON operator, second-order input]
negative_triggers: [generic 500, WAF block, validation error, unstable latency]
blackbox: true
whitebox: true
behavioral_eval_status: fixture
---

# SQL Injection

## Purpose
Determine whether attacker input changes relational query structure rather than merely causing syntax validation, database errors, WAF behavior, or timing noise.

## When to use
Use when input plausibly reaches raw SQL, query-builder fragments, ORM raw/extra/order APIs, identifiers, dynamic sort/filter/field selection, stored procedures, JSON/database operators, or a later second-order query. Parameter values and identifiers have different safe-construction models.

## Process
1. Read references/mental-model.md. Model input → decoding/validation → builder/ORM → parameterization boundary → query role (value, identifier, operator, fragment) → database → application response.
2. Establish a stable baseline and choose one applicable proof: paired boolean differential, bounded syntax/semantic differential, or carefully repeated short timing differential. Error text alone is not injection.
3. Send paired true/false changes through the Broker with equivalent length/shape where possible. Repeat only enough to reject cache/jitter. Never run sqlmap, dump data, stack writes, or enumerate schemas.
4. For dynamic identifiers/order/filter, test allowlisting rather than quote payloads. For second-order behavior, prove storage then later query use as separate steps. For ORM paths, distinguish parameterized values from unsafe raw fragments.
5. Support only a reproducible query-controlled result attributable to the changed expression. Demonstrate the smallest protected effect permitted.

## Evidence
Persist baseline/true/false requests, response-body/status/cardinality features, timing samples and controls when used, query role inferred, repeatability, WAF/cache checks, and minimal demonstrated data/authorization effect. Never store dumped records.

## False positives
Generic database errors, ORM type coercion, validation rejection, WAF signature blocks, search syntax features, cache variance, one latency spike, and a boolean-looking response driven by application logic rather than SQL structure.

## Stop conditions
Stop before data/schema enumeration, UNION extraction, write/stacked statements, long sleeps, lock/contention, high-volume automation, or R3/R4. If paired controls are unstable, mark inconclusive and stop.

Read references/attack-surface.md for query roles, safe proof selection, and framework/ORM notes; use source-dataflow-analysis when code is available.
