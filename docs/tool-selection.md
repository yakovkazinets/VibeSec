# Tool Selection

## Minimal profile

| Tool | Role | License | Execution design |
|---|---|---|---|
| Trivy 0.72.0 | Filesystem dependencies, secrets, and configuration | Apache-2.0 | Official release archive with verified SHA-256 |
| Gitleaks 8.30.1 | Dedicated repository secret detection | MIT | Official release archive with verified SHA-256 |
| actionlint 1.7.12 | GitHub Actions syntax and expression linting | MIT | Official release archive with verified SHA-256 |

Release binaries were chosen over scanner actions to keep execution explicit, avoid unnecessary workflow-token access, and make checksum verification reviewable in `config/tools.json`. GitHub's checkout and artifact actions are pinned to complete commit SHAs with release-tag comments.

Pins reduce exposure to a mutable tag or release asset being replaced, but they do not prove upstream code is safe. Version updates must verify the official repository, release asset, checksum file, license, and release notes together. A checksum mismatch is an installation failure, never permission to substitute an observed checksum automatically.

Selection must follow repository evidence. For example, configuration scanning is relevant only when supported infrastructure or workflow files exist, and adding another dependency scanner to a repository with equivalent controls may create duplicate findings rather than useful coverage.

## Future evaluation

Opengrep, Semgrep, OSV-Scanner, Checkov, ZAP, fuzzing, cosign, SLSA, and OSSF Scorecard remain unimplemented. Before adoption, maintainers must verify current licenses, maintenance, required services, data transmission, rule licenses, release integrity, and overlap. Research notes are inputs, not authority.
