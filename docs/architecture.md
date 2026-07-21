# Architecture

## Goals

VibeSec provides a maintainable, open-source starting point for developers without dedicated security staff: a repository-aware coding-agent skill and a copyable minimal GitHub Actions profile. It prioritizes explicit evidence, safe defaults, small changes, and useful local artifacts.

VibeSec does not replace threat modeling, code review, penetration testing, incident response, or professional judgment. It does not guarantee that an application is secure.

## Components and order

The minimal profile installs checksum-verified release binaries, runs Trivy, Gitleaks, and actionlint, normalizes their output, applies baseline and suppression policy, writes JSON and Markdown reports, then retains only those normalized reports. Installation precedes scanning so an unverified binary cannot influence results. Normalization precedes policy so tool-specific formats cannot silently change enforcement. Raw scanner output stays runner-local because it may contain discovered secret material. Artifact upload runs even after failure so maintainers can distinguish findings from broken tooling.

Trivy provides broad filesystem dependency, secret, and configuration coverage. Gitleaks provides a dedicated second view of secrets. actionlint validates GitHub Actions syntax and common expression problems. Repository-aware selection matters because irrelevant scanners add noise, runtime, and maintenance without adding meaningful coverage.

`.github/workflows/ci.yml` protects VibeSec itself. `templates/github-actions/security-baseline.yml` is the consumer starter. The starter requires the accompanying `scripts/`, `config/`, and `policy/` directories; this avoids downloading mutable VibeSec code at runtime.

## Planned, not implemented

Opengrep, Semgrep, OSV-Scanner, Checkov, ZAP, fuzzing, cosign, SLSA, and OSSF Scorecard are future profile candidates. None is executed or implied by the minimal profile.
