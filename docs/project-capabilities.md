# Project capabilities

`.vibesec/project-capabilities.json` is the authoritative declaration of which project scopes exist. Schema version 1 contains exactly 16 Boolean keys. Unknown or duplicate keys, non-Booleans, malformed or non-UTF-8 input, byte-order marks, oversized files, symlinks, and dependency conflicts fail closed.

`authenticated_security_testing=true` requires `authentication=true` and at least one of `dast_target=true` or `api_security_target=true`. Installation then asks only for the name of the GitHub Actions secret containing the static bearer token. The token value is never accepted. VibeSec itself declares both authentication capabilities false, so authenticated security testing is `not_applicable`.

The initializer asks every question with `[Y/n]`. Enter, `y`, and `yes` mean Yes; `n` and `no` mean No, case-insensitively. Invalid answers are asked again. Every interactive question defaults to Yes, so maintainers must deliberately answer No for absent capabilities. EOF and non-interactive input never invent answers: use `--capabilities-file <trusted-local-json>` or the explicit `--all-capabilities` shorthand. Dry run remains the default and prints the resulting manifest; `--write` is required for atomic creation and never overwrites an existing file.

Dependencies are strict: `dast_target=true` requires `web_application=true`; `api_security_target=true` requires both `api=true` and `container_image=true`; `public_runtime=true` and `authentication=true` each require either `web_application=true` or `api=true`. `web_application=true` with `dast_target=false` is valid. VibeSec never silently rewrites conflicting answers.

Explicit answers override detection. Detection may narrow an enabled capability when no supported artifact exists, but it cannot enable a capability answered No. `infrastructure_as_code=false` makes Checkov `not_applicable`; `container_image=false` makes image scanning `not_applicable`; `github_actions=false` makes actionlint `not_applicable`; `dast_target=false` prevents DAST installation. Gitleaks remains broadly applicable. A scanner is `ran` only after it actually completes.

Validate after manual editing:

```sh
python3 scripts/validate_project_capabilities.py .vibesec/project-capabilities.json
```

`not_applicable` means the declared project capability does not exist. `not_configured` means a relevant optional capability exists but lacks a usable or trusted-event configuration. Neither is a clean scan. Installation verification records the original manifest hash, doctor reports malformed, missing, changed, conflicting, partially installed, or DAST-mismatched state, and the upgrade planner classifies the file as `capability_preserve`. Upgrades never reset No to Yes; newly introduced questions require an explicit non-interactive answer.

VibeSec itself declares `web_application=false`, `dast_target=false`, `api=false`, and `api_security_target=false`. Controlled HTTP and OpenAPI fixtures test optional machinery without turning this toolkit into a web/API product. VibeSec therefore reports both runtime add-ons as `not_applicable`. Enabling either later requires explicit valid capability answers and separate add-on initialization.
