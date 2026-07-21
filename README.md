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

It does not build or execute application code. Standard and Advanced features—including SAST, OSV-Scanner, Checkov, DAST, fuzzing, signing, provenance, and Scorecard—are planned but not implemented.

## Use the starter workflow

Copy the starter and its required local support directories into an application repository:

```shell
mkdir -p .github/workflows
cp templates/github-actions/security-baseline.yml .github/workflows/security-baseline.yml
cp -R scripts config policy /path/to/application/
```

Start with `VIBESEC_ENFORCEMENT: observe`. Review historical findings, record reviewed fingerprints in `policy/baseline.json`, then change to `new` when ready to block newly introduced high or critical findings. See [the security model](docs/security-model.md) and [false-positive guide](docs/false-positive-guide.md).

Pull requests, pushes to `main`, weekly schedules, and manual runs use the same minimal scan. Fork pull requests receive no secrets. Reports remain useful without GitHub Advanced Security and are retained as JSON and Markdown artifacts.

## Develop

```shell
python3 -m unittest discover -s tests -v
scripts/install_tools.sh . .tools/bin
VIBESEC_ENFORCEMENT=observe scripts/run_minimal_profile.sh . results
```

Read [the architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [contribution guide](CONTRIBUTING.md) before changing security-sensitive behavior.

Imported skills can be structurally checked with `python3 scripts/validate_skill.py path/to/skill` after installing `requirements.txt`. See [imported skill validation](docs/skill-validation.md). Validation does not execute or grant authority to imported instructions.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
