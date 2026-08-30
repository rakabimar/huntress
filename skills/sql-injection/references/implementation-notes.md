# Implementation notes

ORM use is not automatically safe. Parameterized ordinary filters are usually safe; raw/extra/native queries, string-built where/order clauses, interpolation, dynamic identifiers, and custom repositories may not be. Record exact API semantics.

Examples of boundaries: Django `raw`/`extra`/RawSQL; SQLAlchemy `text` and string fragments; Rails `find_by_sql`, raw order/where strings; Laravel raw expressions; JPA native queries/string concatenation; Go `database/sql` placeholders versus formatted SQL; Node query builders' raw methods; PHP `$wpdb->prepare` versus direct interpolation. WordPress `$wpdb->prepare` still needs correct placeholders and identifiers need allowlists.

Remediate by parameterizing values, mapping identifiers/operators from allowlists, using typed query APIs, eliminating raw composition, preserving parameters through stored procedures/JSON queries, and adding paired regression tests at the vulnerable construction site.
