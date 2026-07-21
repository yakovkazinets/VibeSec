# Security and Result Model

Each normalized result records `tool`, `category`, `rule_id`, normalized `severity`, `file`, `line`, `description`, `confidence`, `fingerprint`, and `result_type`.

`result_type` has three meanings:

- `finding`: a scanner reported something requiring policy evaluation. It is not automatically a confirmed vulnerability.
- `tool_error`: a scanner, parser, or infrastructure component failed. It must never be reported as a clean scan.
- `pass`: a tool completed without a reportable result. A pass covers only that tool's configured scope.

Exit codes are `0` for completed evaluation without policy violations, `1` for a policy violation, `2` for tool or infrastructure failure, and `3` for invalid configuration or malformed result input.

The initial default is `observe`, which reports findings without blocking. After review, maintainers record historical fingerprints in `baseline.json` and may select `new`, which blocks new findings at or above the threshold. `all` evaluates all unsuppressed findings. Suppressions are never implicit and require fingerprint, reason, owner, and expiration date.

Policy files ending in `.yml` intentionally use JSON syntax, which is valid YAML. The initial Python implementation can therefore parse them with the standard library while remaining consumable by YAML tooling. Malformed policy or scanner input exits `3`; it is not converted into a finding or pass.

SARIF upload is not required by the core profile and is not implemented in this phase. Future optional upload must use a separately scoped job, remain useful when unavailable, and never replace retained local JSON and Markdown reports.
