# Injection-oriented testing

Injection-oriented mode sends only the exact deterministic inert markers in `config/injection-payloads.json`. The reviewed families cover SQL-shaped quoting, command-shaped delimiters, path traversal syntax, template syntax, and encoded header delimiters. Each family declares a stable ID, exact payload, marker ID, allowed parameter locations, expected safe handling, severity, and limitation. Unknown families, altered fields, oversized values, external URLs, callback strings, operational shells, destructive SQL, credential material, or authentication-header locations fail closed.

The launcher selects only string path, query, non-authentication header, and simple JSON object fields from the already validated local OpenAPI document. `Authorization`, `Proxy-Authorization`, `Cookie`, and `Set-Cookie` are never selected. It does not use application examples or publish exact generated values.

A finding requires reviewed evidence: a controlled 5xx, response-schema or status-code violation, exact marker reflection, an allowlisted bounded framework-error shape, or a deterministic semantic mismatch. A timeout, target termination, or unexpected connection closure blocks as runtime failure instead of becoming clean evidence. Merely sending a payload never creates a vulnerability claim. Titles deliberately say “Potential SQL injection handling weakness” and “Potential command injection handling weakness”; evidence reasons and limitations remain attached.

Authenticated injection testing is permitted only when `authentication=true`, `authenticated_security_testing=true`, and the existing fixed bearer configuration is valid. The token is supplied through scanner stdin, used only as the request `Authorization` value, removed from the environment, never mutated, and excluded from arguments, payloads, diagnostics, replay data, and artifacts.

This is input-handling validation, not exploitation. It does not execute commands, query databases, read or create files, contact external systems, persist access, upload files, brute-force credentials, or prove the absence of injection vulnerabilities.
