# Five-minute Quick Start

Passive DAST is not part of either profile. After a valid base installation, maintainers may opt in with `python3 scripts/init_vibesec.py --addon dast-baseline --target <repository> --write`. Enable it only for an authorized non-production immutable non-root image on trusted manual or scheduled events; see [DAST Baseline](dast-baseline.md).

VibeSec is a scanning baseline, not proof that an application is secure. Use a reviewed VibeSec checkout matching the version you intend to adopt. The initializer itself uses no network, installs nothing, executes no application code, and defaults to a preview.

The initializer first asks the [project capability questionnaire](project-capabilities.md). Every question shows `[Y/n]`: Enter is Yes, and you should explicitly answer No for absent scopes. Its dry-run JSON includes the exact manifest and writes nothing. For automation, supply reviewed answers with `--capabilities-file`; do not pipe EOF and assume defaults.

## Choose a profile

Choose **Minimal** for the fastest first baseline: Trivy filesystem, Gitleaks, and actionlint. Choose **Standard** when you need local-rule source analysis, deeper dependency routing, SBOMs, or IaC coverage and can maintain the larger toolchain. Read [profile selection](profile-selection.md) before adding Standard to a repository that already has scanners.

## Minimal: one-stage adoption

From the VibeSec checkout:

```shell
python3 scripts/init_vibesec.py --profile minimal --target /path/to/application
python3 scripts/init_vibesec.py --profile minimal --target /path/to/application --write
```

The first command is a dry run. Review `project_capabilities`, `would_create`, `conflict`, and `warning`; the second creates exactly the catalogued files, including `.vibesec/project-capabilities.json`, `.github/workflows/vibesec-minimal.yml`, required scripts/configuration/policy, `policy/baseline.json`, and `.vibesec/install-minimal-all.json`. Commit and review those files in the application repository.

## Standard: required two-stage bootstrap

Standard pull requests execute a trusted harness taken from the pull request's base commit. A single pull request cannot safely introduce both that harness and a workflow that expects it. First preview and add support files:

```shell
python3 scripts/init_vibesec.py --profile standard --target /path/to/application
python3 scripts/init_vibesec.py --profile standard --target /path/to/application --write
```

Review, merge, and confirm those support files are on the default branch. Then create a second change:

```shell
python3 scripts/init_vibesec.py --profile standard --stage workflow --target /path/to/application
python3 scripts/init_vibesec.py --profile standard --stage workflow --target /path/to/application --write
```

The second stage adds `.github/workflows/vibesec-standard.yml` and a separate installation manifest. Standard requires `scripts/`, `config/`, `policy/`, and `rules/`; it uses `policy/standard-baseline.json` and generates `normalized.json`, `coverage.json`, `inventory.json`, `report.md`, and—when package evidence exists—a separately retained CycloneDX/SPDX SBOM pair.

## Existing repository with no VibeSec files

Run the dry run first. If it reports no conflicts, review warnings for CodeQL, Semgrep, Snyk, Dependabot, Renovate, Trivy, Gitleaks, OSV-Scanner, Checkov, Grype, or Anchore. Existing equivalent coverage is a reason to keep Minimal or adapt deliberately, not to install duplicates automatically.

## Repository with existing security workflows

Do not replace or disable them. The initializer refuses VibeSec filename conflicts and warns about recognizable overlap. Compare scope, event permissions, report destinations, and maintenance ownership using [profile selection](profile-selection.md). Manual adoption remains available: use `config/adoption-files.json` as the authoritative file list, copy the selected template to its catalogued destination byte-for-byte, preserve executable bits, and do not combine Minimal and Standard baselines.

## What the first run does

Both starters begin with `VIBESEC_ENFORCEMENT: observe`. Findings are reported but do not fail policy, allowing historical results to be reviewed before gating. Scanner/tool failure and malformed input still fail closed. Minimal retains `results/normalized.json` and `results/report.md`; Standard retains its required reports from the runner temporary directory and uploads validated SBOMs separately.

Coverage terms are exact:

- `ran`: the component completed in its configured scope; this is not a security guarantee.
- `not_applicable`: the authoritative capability declaration or deterministic evidence excludes that component.
- `not_configured`: optional coverage was absent or prohibited, such as image scanning on a pull request.
- `tool_error`: execution or parsing failed; coverage is unavailable and the run must not be treated as clean.

## Review, baseline, and enforce new findings

Download the JSON and Markdown artifacts, verify tool errors first, then review every finding in repository context. After documenting accepted historical findings, copy only their reviewed fingerprints into the profile-specific baseline and set `generated_at`. Never put Standard fingerprints in `policy/baseline.json` or Minimal fingerprints in `policy/standard-baseline.json`. To move from `observe` to `new`, change the workflow to `VIBESEC_ENFORCEMENT: new` in a separate reviewed change. Use suppressions only with fingerprint, reason, owner, and expiration.

## Network and privacy

The initializer makes no network calls. Workflow tool installation downloads pinned releases. Minimal's Trivy dependency database behavior is scanner-managed; Gitleaks and actionlint operate locally. Standard OSV online mode may send package names, versions, ecosystems, and file hashes to OSV.dev or deps.dev. Offline mode requires a caller-provisioned validated database. Opengrep, Syft, and Checkov do not upload source; Checkov has no network. A trusted-event image scan may contact the referenced registry. SBOMs can expose internal package names and versions.

## Remove VibeSec

Use `.vibesec/install-*.json` as a review checklist. Remove only files that are still VibeSec-owned, preserve any local policy evidence you need, and remove the workflow in a reviewed change. The initializer deliberately has no destructive uninstall or overwrite mode. Removing VibeSec also removes its coverage; it does not resolve findings.

For problems, use [troubleshooting](troubleshooting.md). For upgrades, use [upgrading](upgrading.md).
