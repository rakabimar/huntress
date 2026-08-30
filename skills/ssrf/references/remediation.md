# SSRF remediation

Parse/canonicalize once, allow expected schemes/ports, enforce hostname label and IP-range policy for every DNS answer, bind connection to the validated destination, revalidate every redirect, strip credentials/sensitive headers, bound redirects/time/bytes, and isolate egress. Centralize this client so every importer/webhook/processor uses it.
