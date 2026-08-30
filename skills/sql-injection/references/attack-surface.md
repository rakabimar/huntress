# SQL injection attack surface and safe proof choice

Inspect search, filters, sort/direction, field selection, report builders, admin grids, bulk/export, GraphQL arguments, JSON operators, full-text features, raw ORM clauses, migrations/custom repositories, stored procedures, and later consumers of stored content.

Choose proof from implementation signals:

- stable content/cardinality surface: paired boolean condition with equivalent request shape;
- controlled syntax context: one benign delimiter/error comparison followed by a semantic pair;
- blind stable endpoint: short bounded timing pair with repeated baseline/true/false and jitter controls;
- identifier/order surface: compare allowlisted versus non-allowlisted names/directions; quote payloads may be irrelevant;
- second order: separately evidence storage and later query-triggering action.

Never use data dumping, schema enumeration, file functions, stacked writes, heavy queries, long sleeps, or automated payload spraying. A WAF block only identifies filtering.
