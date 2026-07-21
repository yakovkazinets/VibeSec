# False-Positive and Suppression Guide

First reproduce the result with the same tool version and configuration. Read the affected code or configuration and identify whether the scanner evidence is applicable, reachable, and production-relevant. Separate confirmed vulnerabilities, plausible heuristic findings, and tool errors.

Prefer fixing the cause or narrowing a rule through reviewed configuration. If suppression is justified, add one record to `policy/suppressions.yml` containing:

```json
{
  "finding_fingerprint": "reviewed fingerprint",
  "reason": "Specific technical reason the finding is not applicable",
  "owner": "GitHub handle or team",
  "expiration_date": "2026-12-31"
}
```

The owner is accountable for re-review. The expiration prevents accepted risk from becoming invisible indefinitely. Never suppress a tool failure, remove a scanner, lower a threshold, or edit a baseline merely to make CI green without documenting the decision.
