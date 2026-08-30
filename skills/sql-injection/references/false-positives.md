# SQL injection false positives

Reject generic 500/database messages, ORM/type validation, search-language syntax, WAF signature blocks, reflection, cache/result variation, one latency spike, and boolean-looking application branches unrelated to SQL. Parameterized value queries may still echo quote characters safely; identifier rejection may be correct allowlisting.
