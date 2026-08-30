# Query-construction model

Trace `input → decoding/type coercion → validation → query builder/ORM/raw boundary → query role → database → result shaping`.

Classify the input role before choosing a test:

- value: should be a bound parameter with stable SQL structure;
- identifier: table/column/sort field cannot usually use value placeholders and needs an allowlist/mapping;
- operator/fragment: dynamic filters, directions, JSON paths, clauses, stored-procedure names need constrained construction;
- stored/second-order value: safe initial storage may become unsafe when later concatenated.

Evidence hierarchy: parser/syntax anomaly < database-looking error < stable timing/boolean differential < demonstrated query-controlled protected effect. Only the latter differentials support injection; impact remains limited to what is demonstrated.
