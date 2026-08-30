# Engagement validation

Imported programs add a precondition to the existing engagement validator: a human-approved intake revision must exist, its normalized draft and canonical authorization hashes must still match, no critical ambiguity may remain open, no unresolved restrictive overlay may exist, and official program state must permit testing.

Legacy/manual programs continue through the established validation path. Approval invokes the existing Pydantic engagement loader/validator; intake does not implement a parallel Scope or Policy engine.
