# Passive ZAP baseline fixture

`server.py` is a VibeSec-owned, standard-library-only HTTP service. `/positive` omits the anti-clickjacking header for passive rule `10020`; `/negative` includes it. The service has no request bodies, state changes, credentials, file access, subprocesses, redirects, or outbound requests. `/external-link` proves the internal Docker network prevents external crawling without contacting a real host.

The checked-in raw documents are untrusted parser fixtures. They intentionally contain query, parameter, description, and evidence values that must not survive normalization.
