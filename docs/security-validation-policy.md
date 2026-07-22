# Security validation policy

VibeSec must be accountable to every security capability it advertises. Integration code alone is incomplete. A capability is complete only when it is implemented, exercised, normalized or structurally validated, documented, and continuously enforced.

`config/security-capabilities.json` is the authoritative, strict, versioned accountability matrix. Every capability must have a unique ID and identify its profile, category, component or pinned tool, version source, positive and negative fixture directories, expected metadata, exact expected coverage state and finding IDs, mandatory artifacts, network/privacy behavior, trusted-event restriction, self-repository state, limitations, CI enforcement, and status rationale. Unknown fields, unsafe paths, duplicate IDs, missing fixtures, missing tools, drifted documentation, or unenforced claims fail repository validation.

## Fixture and evidence requirements

Each capability directory under `tests/security-fixtures/` contains `positive/`, `negative/`, `expected.json`, and `README.md`. Fixtures must be tiny, deterministic, non-operational, independent from project installation, and safe to publish. Exact counts are required when the controlled input is deterministic. A bounded range is permitted only with a written instability reason, a narrow minimum and maximum, and exact invariant fields; the current matrix uses exact counts.

Positive findings must retain tool, category, stable rule or advisory ID, severity, repository-relative path, line where available, safe description, confidence, fingerprint, and result type. CWE and remediation are maintained in VibeSec-owned Opengrep rule metadata; scanner output never retains full source snippets. Secret fixtures may use only the documented non-operational marker and normalized or uploaded reports must omit its value.

For each scanner, CI must cover non-zero execution, missing executable, malformed, truncated, oversized, wrong-schema, and stale-output behavior where supported. A scanner or parser failure is `tool_error` or invalid input, never zero findings and never clean. `not_configured` and `not_applicable` are explicit coverage states, not successful execution.

## Trust and artifacts

Expected metadata, the matrix, schemas, scanner scripts, rules, configuration, policies, baselines, and suppressions are trusted repository code. Pull-request target content is scan data only and cannot replace the base-revision harness. Fork-like tests enforce no secrets, no private-registry authority, disabled image scanning, immutable action pins, `contents: read`, and sanitized mandatory artifacts.

Minimal requires normalized JSON, escaped Markdown, coverage JSON, and a policy-result artifact. Standard additionally requires repository inventory, exact tool coverage, validated CycloneDX and SPDX SBOMs when Syft runs, and separate optional artifact handling. Raw scanner output is never uploaded.

## Scanner updates

A tool or rule update must change the matrix and fixtures in the same review. Record the old and new versions, checksum/signature/digest verification, positive and negative result changes, normalization/schema changes, runtime, network/privacy behavior, false positives, removed findings, and the review conclusion. Run the full accountability suite before accepting changed counts or severities. Never weaken an expectation solely to make CI pass.

Passing accountability and self-scans prove only that configured checks behaved as expected within their tested scope. They do not prove VibeSec or an application is secure.
