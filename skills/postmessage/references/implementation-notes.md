# Implementation notes

Search addEventListener/message/onmessage and postMessage across bundles/source maps. React/Vue wrappers do not add security automatically. OAuth/payment SDK messages must bind state/transaction and issuer/provider origin. Avoid suffix or substring origin checks and never treat message fields as authenticated identity.
