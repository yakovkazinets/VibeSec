# VibeSec

VibeSec is an open-source application-security toolkit for vibe coders, solo developers, startups, and small teams. It combines a repository-aware coding-agent skill with a copyable GitHub Actions baseline.

VibeSec cannot guarantee that an application is secure. Scanner coverage is incomplete, findings may be wrong, and a clean scan covers only the checks that completed successfully.

## Maintainer note and disclaimer

VibeSec was created by a practicing cybersecurity engineer with relevant security certifications, but I do not claim to be a foremost expert in every area of application security. This project was also developed in part through AI-assisted—or “vibe coding”—workflows, supported by technical research, automated testing, and manual review.

AI-assisted development can introduce mistakes, incomplete assumptions, insecure patterns, and subtle implementation defects. VibeSec should therefore be treated as an opinionated starting point, not as proof that an application is secure or as a substitute for threat modeling, secure design review, penetration testing, or review by qualified security professionals.

Review the code and configuration before using it, validate it against your own environment and risk model, and report anything that appears incorrect or unsafe. Independent review and security-focused contributions are strongly encouraged.

## Minimal profile

The initial profile uses:

- Trivy for filesystem dependency, secret, and configuration scanning.
- Gitleaks for dedicated secret detection.
- actionlint for GitHub Actions syntax and expression checks.

It does not build or execute application code. Advanced features—including DAST, fuzzing, provenance, and Scorecard—are not implemented.

## Standard profile

The opt-in Standard profile preserves the Minimal controls and adds:

- VibeSec-owned Opengrep rules for JavaScript/TypeScript, Python, Java, and Go SAST.
- OSV-Scanner v2 as the primary source-dependency advisory scanner.
- Syft filesystem SBOMs in CycloneDX JSON and SPDX JSON.
- Checkov only when supported infrastructure-as-code is detected.
- Optional Trivy scanning of an already-built image, only on trusted events and only by immutable digest.
- A deterministic repository inventory and coverage report that distinguishes `ran`, `not_applicable`, `not_configured`, and `tool_error`.

The profile never installs project dependencies, runs lifecycle scripts, builds the application, builds a Dockerfile, applies infrastructure, or uploads source to a commercial service. Trivy is limited to secrets and configuration in this profile so OSV-Scanner remains the primary source-dependency scanner. See [tool selection](docs/tool-selection.md) for overlap and network behavior.

## Use the starter workflow

Copy the starter and its required local support directories into an application repository:

```shell
mkdir -p .github/workflows
cp templates/github-actions/security-baseline.yml .github/workflows/security-baseline.yml
cp -R scripts config policy /path/to/application/
```

Start with `VIBESEC_ENFORCEMENT: observe`. Review historical findings, record reviewed fingerprints in `policy/baseline.json`, then change to `new` when ready to block newly introduced high or critical findings. See [the security model](docs/security-model.md) and [false-positive guide](docs/false-positive-guide.md).

Pull requests, pushes to `main`, weekly schedules, and manual runs use the same minimal scan. Fork pull requests receive no secrets. Reports remain useful without GitHub Advanced Security and are retained as JSON and Markdown artifacts.

For Standard, copy `templates/github-actions/security-standard.yml` instead and keep the accompanying `scripts/`, `config/`, `policy/`, and `rules/` directories. Standard uses `policy/standard-baseline.json`; Minimal continues to use `policy/baseline.json`. Start in observation mode. Do not treat the two baselines as interchangeable.

On pull requests, the Standard starter materializes `scripts/`, `config/`, `policy/`, and `rules/` from the pull request's base commit into the runner temporary directory. The checked-out pull-request tree is only the scan target; its VibeSec scripts, scanner configuration, ignore files, and policy cannot replace the trusted harness. VibeSec's own development CI deliberately tests the changed implementation, but remains read-only and receives no secrets.

OSV-Scanner defaults to online advisory lookup, which can send package names, versions, ecosystems, and file hashes to OSV.dev or deps.dev. Offline mode requires `VIBESEC_OSV_DATABASE_DIR`, `VIBESEC_OSV_DATABASE_DATE=YYYY-MM-DD`, and an optional `VIBESEC_OSV_MAX_DATABASE_AGE_DAYS` (default `7`). VibeSec validates the caller-provisioned `<ecosystem>/all.zip` files and their declared age but never downloads or refreshes them. Checkov runs with network disabled. Syft update checks, enrichment, and remote metadata lookup are disabled. Raw scanner outputs are not uploaded. SBOM artifacts can disclose internal package names and versions; the starter retains them separately for 14 days.

## Develop

```shell
python3 -m unittest discover -s tests -v
scripts/install_tools.sh . .tools/bin
VIBESEC_ENFORCEMENT=observe scripts/run_minimal_profile.sh . results
scripts/install_standard_tools.sh . .tools/bin
VIBESEC_ENFORCEMENT=observe python3 scripts/run_standard_profile.py . results
```

Read [the architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [contribution guide](CONTRIBUTING.md) before changing security-sensitive behavior.

Imported skills can be structurally checked with `python3 scripts/validate_skill.py path/to/skill` after installing `requirements.txt`. See [imported skill validation](docs/skill-validation.md). Validation does not execute or grant authority to imported instructions.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
