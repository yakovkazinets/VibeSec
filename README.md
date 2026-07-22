# VibeSec

The [Passive DAST Baseline add-on](docs/dast-baseline.md) is deliberately outside the Minimal and Standard profiles. It is manual/scheduled, unauthenticated, passive-only, and limited to an explicitly configured immutable non-root image on an isolated internal Docker network. Review its [threat model](docs/dast-threat-model.md) before enabling it.

The [API Security Baseline add-on](docs/api-security-baseline.md) is also separate and opt-in. It uses a local OpenAPI 3.x contract and an immutable non-root API image on trusted manual/scheduled events, defaults to GET/HEAD/OPTIONS, and never accepts credentials or public targets. Review its [threat model](docs/api-security-threat-model.md).

[Authenticated security testing](docs/authenticated-security-testing.md) is a bearer-only opt-in for eligible DAST or API targets. The GitHub secret is scoped to the exact scanner step, passed to the fixed scanner launcher over stdin, and excluded from configuration, arguments, reports, diagnostics, and artifacts. Review the dedicated [threat model](docs/authenticated-security-threat-model.md).

VibeSec is an open-source application-security toolkit for vibe coders, solo developers, startups, and small teams. It combines a repository-aware coding-agent skill with a copyable GitHub Actions baseline.

VibeSec cannot guarantee that an application is secure. Scanner coverage is incomplete, findings may be wrong, and a clean scan covers only the checks that completed successfully.

## Maintainer note and disclaimer

VibeSec was created by a practicing cybersecurity engineer with relevant security certifications, but I do not claim to be a foremost expert in every area of application security. This project was also developed in part through AI-assisted—or “vibe coding”—workflows, supported by technical research, automated testing, and manual review.

AI-assisted development can introduce mistakes, incomplete assumptions, insecure patterns, and subtle implementation defects. VibeSec should therefore be treated as an opinionated starting point, not as proof that an application is secure or as a substitute for threat modeling, secure design review, penetration testing, or review by qualified security professionals.

Review the code and configuration before using it, validate it against your own environment and risk model, and report anything that appears incorrect or unsafe. Independent review and security-focused contributions are strongly encouraged.

## Start here

- [Five-minute Quick Start](docs/quickstart.md)
- [Minimal versus Standard](docs/profile-selection.md)
- [Compatibility matrix](docs/compatibility.md)
- [Configuration reference](docs/configuration.md)
- [Project capability questionnaire](docs/project-capabilities.md)
- [Troubleshooting and preflight](docs/troubleshooting.md)
- [Upgrading](docs/upgrading.md)
- [Consumer distribution](docs/distribution.md), [installation verification](docs/installation-verification.md), and [doctor](docs/doctor.md)
- [Software supply-chain assurance](docs/software-supply-chain-assurance.md), [release signing](docs/release-signing.md), [provenance](docs/provenance.md), and the [release threat model](docs/release-threat-model.md)
- [Sanitized sample reports](examples/reports/README.md)
- [Security/result model](docs/security-model.md) and [threat model](docs/threat-model.md)
- [Security validation policy](docs/security-validation-policy.md), [capability matrix](docs/security-capability-matrix.md), and [self-hosted validation](docs/self-hosted-validation.md)
- [Finding intelligence](docs/finding-intelligence.md) and [framework SAST coverage](docs/framework-sast-coverage.md)
- [GitHub Actions Node 24 runtime and immutable pin policy](docs/github-actions-runtime.md)
- [OpenAPI API Security Baseline](docs/api-security-baseline.md)

Supplied workflows target GitHub.com and require Actions Runner 2.327.1 or newer on self-hosted runners. Their reviewed JavaScript actions embed Node 24 and use full commit SHAs; Node 20 is end-of-life and unsupported, and no fallback is provided. VibeSec itself requires no npm or Node application runtime. Node 26 remains a future compatibility target rather than a requirement. See the runtime policy for the separate GHES limitation.

Minimal uses Trivy filesystem, Gitleaks, and actionlint. Standard adds framework-aware VibeSec-owned Opengrep rules, OSV-Scanner, Syft SBOMs, conditional isolated Checkov, deterministic finding correlation and explainable priority, explicit coverage reporting, and optional trusted-event scanning of an existing immutable image. Original findings and baseline fingerprints remain authoritative. Neither profile builds or executes application code, installs project dependencies, builds Dockerfiles, or applies infrastructure. Separate opt-in add-ons provide passive ZAP DAST and bounded Schemathesis OpenAPI contract testing against explicitly supplied immutable, non-root images.
<!-- claimed-scanners: actionlint,checkov,gitleaks,opengrep,osv-scanner,schemathesis,syft,trivy,zap-baseline -->

Preview adoption without changing the application repository:

```shell
python3 scripts/init_vibesec.py --profile minimal --target /path/to/application
python3 scripts/init_vibesec.py --profile standard --target /path/to/application
```

The initializer asks 16 project-capability questions, each displayed with `[Y/n]` and defaulting to Yes. Answer No when a capability does not apply. Non-interactive use requires `--capabilities-file <trusted-local-json>` or the explicit `--all-capabilities` option; EOF never supplies defaults. The resulting `.vibesec/project-capabilities.json` is authoritative for scanner applicability. When authenticated testing is enabled, supply only `--auth-secret-name`; never supply the token.

Add `--write` only after reviewing the machine-readable plan. Minimal is one stage. Standard deliberately requires support files to land on the default branch before `--stage workflow` is initialized in a second change, preserving the base-revision trusted-harness boundary. Existing-file conflicts are never overwritten.

For offline distribution, build and verify a deterministic consumer ZIP, then pass it to the initializer with `--bundle`. Future official release candidates add strict manifests, checksums, signed checksum metadata, SBOM identity, and SLSA-aligned provenance outside the reproducible ZIP. Verify those files with a separately trusted copy of `scripts/verify_release_artifacts.py`; never bootstrap trust by executing an unverified downloaded script. Check installed support with `scripts/verify_installation.py`, diagnose it offline with `scripts/vibesec_doctor.py`, and compare it to a newer verified bundle with the read-only `scripts/plan_vibesec_upgrade.py`. Local development bundles remain unsigned; signature validity proves identity and integrity, not application security.

Both profiles start in `observe`; findings are visible while tool/parser failures still fail closed. After review, populate only the matching profile baseline and move to `new`. Manual adopters can use `config/adoption-files.json` as the authoritative file list and copy the matching workflow byte-for-byte; preserve executable modes and never interchange baselines.

Fork pull requests receive no secrets or registry credentials. Raw scanner output is not uploaded. Standard OSV online mode may send package metadata and file hashes; SBOMs may disclose internal package names/versions. Read the Quick Start before enabling it in a private repository.

## Develop

```shell
python3 -m unittest discover -s tests -v
scripts/install_tools.sh . .tools/bin
VIBESEC_ENFORCEMENT=observe scripts/run_minimal_profile.sh . results
scripts/install_standard_tools.sh . .tools/bin
VIBESEC_ENFORCEMENT=observe python3 scripts/run_standard_profile.py . results
```

Read [the architecture](docs/architecture.md), [tool selection](docs/tool-selection.md), [threat model](docs/threat-model.md), and [contribution guide](CONTRIBUTING.md) before changing security-sensitive behavior.

Every advertised capability must have maintained positive and negative fixtures, controlled failure evidence, artifact validation, and mandatory CI enforcement. Fixture guidance and self-scan expectations are documented in [self-hosted validation](docs/self-hosted-validation.md).

Imported skills can be structurally checked with `python3 scripts/validate_skill.py path/to/skill` after installing `requirements.txt`. See [imported skill validation](docs/skill-validation.md). Validation does not execute or grant authority to imported instructions.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
