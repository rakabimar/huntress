# Source/runtime mapping

A mapping joins a source repository and commit to a runtime endpoint or released
artifact. It records source surface, runtime target/version, method, confidence,
and evidence. Method/path shape correlation is useful but not proof of deployed
version.

Signals may include a version endpoint, response headers, asset hashes, release
metadata, API behavior, or program-provided version. Keep confidence explicit;
do not force ambiguous mappings.

An observation on `main` commit B cannot become a production claim when runtime
evidence maps to release commit A. Both source→runtime and runtime→source are
supported: correlate extracted routes to recon endpoints, or search a suspicious
Burp endpoint back to its route/controller and security controls.
