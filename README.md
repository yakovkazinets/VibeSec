# VibeSec

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
- [Troubleshooting and preflight](docs/troubleshooting.md)
- [Upgrading](docs/upgrading.md)
- [Consumer distribution](docs/distribution.md), [installation verification](docs/installation-verification.md), and [doctor](docs/doctor.md)
- [Sanitized sample reports](examples/reports/README.md)
- [Security/result model](docs/security-model.md) and [threat model](docs/threat-model.md)

Minimal uses Trivy filesystem, Gitleaks, and actionlint. Standard adds VibeSec-owned Opengrep rules, OSV-Scanner, Syft SBOMs, conditional isolated Checkov, explicit coverage reporting, and optional trusted-event scanning of an existing immutable image. Neither profile builds or executes application code, installs project dependencies, builds Dockerfiles, applies infrastructure, or performs DAST/fuzzing/runtime analysis.

Preview adoption without changing the application repository:

```shell
python3 scripts/init_vibesec.py --profile minimal --target /path/to/application
python3 scripts/init_vibesec.py --profile standard --target /path/to/application
```

Add `--write` only after reviewing the machine-readable plan. Minimal is one stage. Standard deliberately requires support files to land on the default branch before `--stage workflow` is initialized in a second change, preserving the base-revision trusted-harness boundary. Existing-file conflicts are never overwritten.

For offline distribution, build and verify a deterministic consumer ZIP, then pass it to the initializer with `--bundle`. Check installed support with `scripts/verify_installation.py`, diagnose it offline with `scripts/vibesec_doctor.py`, and compare it to a newer verified bundle with the read-only `scripts/plan_vibesec_upgrade.py`. Development bundles are unsigned; validity does not prove publisher identity or application security.

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

Imported skills can be structurally checked with `python3 scripts/validate_skill.py path/to/skill` after installing `requirements.txt`. See [imported skill validation](docs/skill-validation.md). Validation does not execute or grant authority to imported instructions.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
