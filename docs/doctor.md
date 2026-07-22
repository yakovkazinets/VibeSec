# VibeSec doctor

For an installed DAST add-on, doctor validates redacted image-reference syntax, port, base path, enforcement settings, and Docker availability. It does not pull or inspect an image, start containers, contact a registry, or assert that the target is secure. Runtime image-user validation remains part of the trusted-event runner.

The doctor performs bounded, read-only, offline diagnostics:

```shell
python3 scripts/vibesec_doctor.py --target /path/to/app
python3 scripts/vibesec_doctor.py --target /path/to/app --profile standard --json
```

It starts with installation verification, then checks runtime assumptions, profile/stage consistency, configuration and policy parsing, action pins and workflow safety, optional Docker relevance, OSV offline metadata, immutable image references, fork restrictions, security-workflow overlap, development-version drift, and unsupported-repository indicators.

For authenticated testing, doctor validates the dependency rules, strict secret name, fixed bearer model, and exact workflow placement. It reports literal credentials, bearer values, JWT-like material, unsupported modes, public or raw-report markers, PR/push/reusable triggers, dynamic secret expressions, secret references outside the scanner environment assignment, upload exposure, and authenticated workflow material when the capability is false. Diagnostics redact values and never inspect the GitHub secret itself.

Doctor reports `GITHUB_ACTION_NODE20_PIN` when an installed VibeSec workflow still contains a known checkout v4.2.2 or upload-artifact v4.6.2 pin. The repair is a reviewed, preservation-aware upgrade to the inventory's Node 24 pin—not a fallback override. Doctor cannot query the runner service, so self-hosted maintainers must confirm Actions Runner 2.327.1 or newer separately.

Doctor also validates the strict project capability manifest and detects missing or malformed data, unknown capabilities, dependency conflicts, changes since installation, partial installation, DAST installed while `dast_target=false`, and missing DAST support while `dast_target=true`. It reports `not_applicable` separately from `not_configured` and never translates either into a clean scan.

Every diagnostic contains a stable code, component, severity, explanation, next action, and documentation reference. `error` is blocking; `warning` records drift, reduced coverage, or a review decision; `informational` records context; `not_applicable` is not a pass.

JSON uses the common command envelope. Exit `0` is healthy, `1` means warnings or drift, `2` means diagnosed verification failure, `3` means invalid input, and `4` means infrastructure failure. Parser/configuration errors remain distinct from findings and clean scanner results.

The doctor prints supported environment-variable names and safe classifications only. It never dumps the environment, secrets, credentials, source snippets, or raw scanner output. Optional tools are checked only when relevant. Unsupported repositories are explicitly outside coverage rather than clean.

Follow the referenced document and make the smallest reviewable repair. Preserve local baselines, suppressions, ignores, and policy until their intent is understood. Configuration health does not establish that the application is secure.

For an installed API Security Baseline, doctor checks applicability, Docker availability, local schema presence and structural restrictions, immutable image syntax, unsupported authentication/headers/external targets/host networking/raw uploads, and overlapping API scanners. When the immutable image is already local, doctor inspects its declared user without pulling it and rejects root or unspecified users; otherwise the runtime performs that mandatory check after its immutable pull. A missing schema or image is `not_configured`; runtime or parser failure is `tool_error`; capability false is `not_applicable`.
