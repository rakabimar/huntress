# Implementation notes

Search for direct status assignments, client-supplied step/status, separate controllers duplicating transitions, jobs consuming stale snapshots, approval records not bound to later values, and endpoints checking only that a token exists. State-machine libraries help only if all write paths use them.
