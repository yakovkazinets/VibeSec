# VibeSec doctor

The doctor performs bounded, read-only, offline diagnostics:

```shell
python3 scripts/vibesec_doctor.py --target /path/to/app
python3 scripts/vibesec_doctor.py --target /path/to/app --profile standard --json
```

It starts with installation verification, then checks runtime assumptions, profile/stage consistency, configuration and policy parsing, action pins and workflow safety, optional Docker relevance, OSV offline metadata, immutable image references, fork restrictions, security-workflow overlap, development-version drift, and unsupported-repository indicators.

Every diagnostic contains a stable code, component, severity, explanation, next action, and documentation reference. `error` is blocking; `warning` records drift, reduced coverage, or a review decision; `informational` records context; `not_applicable` is not a pass.

JSON uses the common command envelope. Exit `0` is healthy, `1` means warnings or drift, `2` means diagnosed verification failure, `3` means invalid input, and `4` means infrastructure failure. Parser/configuration errors remain distinct from findings and clean scanner results.

The doctor prints supported environment-variable names and safe classifications only. It never dumps the environment, secrets, credentials, source snippets, or raw scanner output. Optional tools are checked only when relevant. Unsupported repositories are explicitly outside coverage rather than clean.

Follow the referenced document and make the smallest reviewable repair. Preserve local baselines, suppressions, ignores, and policy until their intent is understood. Configuration health does not establish that the application is secure.
