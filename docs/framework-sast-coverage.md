# Framework SAST coverage

The Standard profile includes 32 locally maintained Opengrep rules. Each has a stable ID, framework and language metadata, severity, confidence, CWE, remediation, false-positive notes, a safe positive fixture, and a reviewed negative fixture. CI requires exactly one positive match per rule and zero negative-fixture matches.

Focused coverage includes Express request-controlled redirects, file paths, commands, templates, and permissive CORS; Next.js redirects, filesystem reads, and public secret-shaped variables; React dangerous HTML; Flask debug, path, redirect, command, and deserialization patterns; Django raw SQL, CSRF exemption, and unsafe HTML marking; FastAPI path, command, deserialization, and CORS patterns; and Spring command, redirect, path, deserialization, CORS, raw SQL, and actuator patterns. Four language-generic starter rules remain.

These narrow starter rules do not provide comprehensive taint tracking, prove attacker control, understand custom validation helpers, or replace manual review. A match may be safe after validation not visible to the rule; a non-match does not prove safety. Rules intentionally avoid import-only detection.

Run structural validation and the pinned scanner fixtures with:

```shell
python3 scripts/validate_opengrep_rules.py
python3 scripts/test_opengrep_rules.py .tools/bin/opengrep
```
