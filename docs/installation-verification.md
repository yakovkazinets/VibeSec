# Installation verification

Modern installations include `.vibesec/project-capabilities.json` in the hashed installation record. Verification fails closed when it is missing, malformed, unsafe, or dependency-conflicting, and reports later edits as local changes. Doctor adds capability-specific diagnostics. Verification proves configuration integrity only; it does not prove that a declared scanner ran or that the project is secure.

When authenticated testing is enabled, the same base installation manifest hashes `.vibesec/authenticated-security-testing.json`. Verification requires the file to contain only the secret name and fixed `Authorization`/`Bearer` declaration, rejects missing configuration, and rejects configuration when the capability is false. It never verifies or accepts a token value.

An installed DAST Baseline add-on has its own `install-addon-dast-baseline.json` manifest and must coexist with exactly one Minimal or Standard base profile. Verification requires the exact add-on support/workflow set and correct DAST baseline profile. Partial, conflicting, locally changed, or wrong-profile policy state remains visible and is not scanner evidence.

Run the read-only verifier from an installed VibeSec support set:

```shell
python3 scripts/verify_installation.py --target /path/to/app
python3 scripts/verify_installation.py --target /path/to/app --json
```

Schema 2 manifests under `.vibesec/` record profile and stage, development version, source type, optional source commit, bundle-manifest hash, expected SHA-256 and mode per installed file, enforcement default, and initializer network behavior.

Statuses are:

- `valid`: declared files, modes, hashes, profile, stages, and workflow boundaries match.
- `valid_with_local_changes`: content differs but remains structurally interpretable; policy changes may be intentional.
- `partial`: one or more declared files are missing.
- `conflict`: manifests or profile/stage combinations compete.
- `invalid`: a manifest, path, type, mode, baseline, support set, or workflow safety property is invalid.
- `unverifiable_legacy_installation`: no manifest exists or schema 1 lacks hashes and modes.

Minimal uses only `policy/baseline.json`; Standard uses only `policy/standard-baseline.json`. Standard workflow installation requires its support-stage manifest and files. Workflows are checked against the strict Node 24 action inventory for exact full SHAs, adjacent release/runtime comments, disabled checkout credential persistence, safe artifact inputs, least-privilege contents access, identifiable enforcement, absence of `pull_request_target`, and matching support files.

Verification is offline and does not resolve action tags. A self-hosted consumer must separately confirm Actions Runner 2.327.1 or newer; GitHub-hosted runners satisfy this baseline. Node 20 is unsupported, and the GitHub.com templates have the documented GHES artifact-action limitation. See [GitHub Actions runtime and pin policy](github-actions-runtime.md).

Never replace local baselines, suppressions, ignore files, policy, or workflows merely because they differ. A wrong executable mode, symlink replacement, unsafe path, malformed manifest, or mismatched workflow/support set is blocking; changed policy content is drift for human review.

Legacy manifests are parsed only with their exact known schema and are not upgraded or reinterpreted. Verification is offline and makes no changes. It checks installation integrity and trust boundaries, not scanner effectiveness, vulnerabilities, CI history, branch protection, or application security.

The API add-on has `.vibesec/install-addon-api-security-baseline.json` plus a hashed `.vibesec/api-security-baseline.json`. Verification requires the independent API policy/configuration, runner, parser, validator, and manual/scheduled workflow as one version-compatible set. It never interprets a changed target configuration as proof that a scan ran.
