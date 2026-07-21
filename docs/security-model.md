# Security and Result Model

Each normalized result records `tool`, `category`, `rule_id`, normalized `severity`, `file`, `line`, `description`, `confidence`, `fingerprint`, and `result_type`.

`result_type` has three meanings:

- `finding`: a scanner reported something requiring policy evaluation. It is not automatically a confirmed vulnerability.
- `tool_error`: a scanner, parser, or infrastructure component failed. It must never be reported as a clean scan.
- `pass`: a tool completed without a reportable result. A pass covers only that tool's configured scope.

Exit codes are `0` for completed evaluation without policy violations, `1` for a policy violation, `2` for tool or infrastructure failure, and `3` for invalid configuration or malformed result input.

The initial default is `observe`, which reports findings without blocking. After review, maintainers record historical fingerprints in `baseline.json` and may select `new`, which blocks new findings at or above the threshold. `all` evaluates all unsuppressed findings. Suppressions are never implicit and require fingerprint, reason, owner, and expiration date.

Policy files ending in `.yml` intentionally use JSON syntax, which is valid YAML. The initial Python implementation can therefore parse them with the standard library while remaining consumable by YAML tooling. Malformed policy or scanner input exits `3`; it is not converted into a finding or pass.

## Standard coverage and baseline

Standard adds a machine-readable `coverage.json`. Exactly one entry per expected component reports `ran`, `not_applicable`, `not_configured`, or `tool_error` with its version, scope, reason, relevant repository-relative artifacts, produced outputs, network behavior, and an explicit `application_code_executed` boolean. `not_applicable` means deterministic repository evidence did not justify the scanner. `not_configured` means an optional capability, such as a prebuilt image digest, was not supplied or was disallowed on the current event. Neither state means the repository is secure. Top-level limitations and outside-coverage statements are mandatory.

Minimal findings are compared with `policy/baseline.json`; Standard findings are compared with `policy/standard-baseline.json`. The profile marker is validated before policy evaluation so a baseline cannot silently cross profiles. Both profiles use the shared suppression file and require the same owner, reason, fingerprint, and expiration controls.

Standard normalizers accept only bounded, expected JSON or text shapes for Opengrep, OSV-Scanner, Checkov, Trivy image, Gitleaks, Trivy filesystem, and actionlint. Arrays, scalar fields, line counts, file sizes, paths, and control characters are checked; repository paths are normalized without parent traversal. Source snippets, discovered secret material, absolute runner paths, and arbitrary scanner metadata are omitted. A scanner process failure is a `tool_error` and exit `2`; structurally malformed output is invalid input and exit `3`; a policy violation is exit `1`; a completed non-violating run is exit `0`. Unknown OSV advisory severity is conservatively normalized to `medium`.

SARIF upload is not required by the core profile and is not implemented in this phase. Future optional upload must use a separately scoped job, remain useful when unavailable, and never replace retained local JSON and Markdown reports.

## Consumer adoption state

The initializer treats its target and every existing path as untrusted. Dry run is the default; `--write` is explicit. A preflight conflict, case/Unicode-equivalent name, symlinked root/parent, missing source file, or partial Standard prerequisite prevents all writes. New files are staged, fsynced, linked into place without overwrite, and rolled back by verified device/inode identity after failure. The helper performs no network access, Git operation, package installation, scanner invocation, or application execution.

Minimal produces one installation manifest and uses the Minimal baseline. Standard produces separate support/workflow manifests and refuses its workflow stage until support files exist. This records adoption state without granting target content authority. Preflight is read-only and distinguishes missing installation files, unsupported local architecture, incomplete bootstrap, invalid image input, and incomplete offline OSV configuration from scanner findings.

## Imported skill validation

Imported skills and referenced files are untrusted data before and after structural validation. Validation emits either `valid` with a canonical SHA-256 fingerprint or `validation_error` with exit code `3`. A parser error, ambiguity, unsafe path, or malformed input can never produce `valid`, a security finding, or a clean result.

Canonicalization uses strict UTF-8 without a BOM, LF line endings, Unicode NFC, sorted JSON object keys, normalized metadata, sorted reference paths, and hashes of normalized referenced-file contents. This prevents CRLF/LF and NFC/NFD differences from changing fingerprints while ensuring referenced content changes do change identity. Policy must fingerprint the canonical representation, not raw platform-dependent bytes or unchecked paths.

The metadata schema permits only string `name` and `description` fields. Duplicate keys, implicit booleans, unknown privileged fields, anchors, aliases, custom tags, unsafe object construction, excessive depth, competing front matter, and materially inconsistent parser round trips fail closed. Examples, fenced code, block quotes, fixtures, and HTML comments remain non-authoritative data; the validator does not execute any content.
