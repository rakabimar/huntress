# GraphQL execution and authorization model

An operation expands into resolver decisions. Model `operation → root field → resolver → loader/service → object → nested field resolvers`. Each field may have distinct authorization and data-loading behavior. HTTP endpoint authentication does not prove resolver authorization.

Create a resolver matrix with operation type, field path, object/tenant source, required principal/role, side effect, batching/data-loader use, and error/null behavior. Global IDs are locators, not authorization tokens.

GraphQL may return HTTP 200 with partial data and errors. Judge the protected field/action/event, not the HTTP status. Introspection reveals schema; it is reportable only when it directly exposes protected secrets/data or violates explicit program policy with demonstrated impact.
