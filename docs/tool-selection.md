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

## Standard profile

| Tool | Role | License | Pin and execution design |
|---|---|---|---|
| Opengrep 1.25.0 | Local-rule SAST for JavaScript/TypeScript, Python, Java, and Go | LGPL-2.1 | Official binary, SHA-256 pin, and Sigstore signature verified against the upstream release workflow identity |
| OSV-Scanner 2.4.0 | Primary source-dependency advisory scanner | Apache-2.0 | Official binary with SHA-256 pin; source scan only, never fix or call analysis |
| Syft 1.49.0 | Filesystem CycloneDX JSON and SPDX JSON SBOMs | Apache-2.0 | Official archive with SHA-256 pin; no enrichment or update check |
| Checkov 3.3.8 | Conditional IaC policy checks | Apache-2.0 | Official container pinned to `sha256:c64ffb6d6fc8087c896341a2c697770a04a1cf558db04fa7b8129d8ca6bce336`; network and external modules disabled |
| Trivy 0.72.0 | Filesystem secret/configuration checks and optional prebuilt-image vulnerabilities | Apache-2.0 | Reuses the Minimal verified binary; image mode requires a digest and trusted event |
| cosign 3.1.2 | Verify the Opengrep release signature | Apache-2.0 | Official binary with SHA-256 pin; installation-only trust helper |

Gitleaks and actionlint remain active from Minimal. Standard intentionally removes Trivy source-dependency vulnerability scanning so OSV-Scanner is the primary source-dependency engine. Trivy remains for secrets and configuration, where overlap with Gitleaks and Checkov is useful but visible. Checkov is conditional on detected IaC; Opengrep is conditional on supported first-party source; OSV and Syft are conditional on supported manifests. Coverage records make these decisions reviewable.

The local Opengrep rules are original VibeSec Apache-2.0 content with per-rule provenance, CWE, OWASP, confidence, remediation, and license metadata. The validator prohibits autofixes and unsupported languages. Opengrep receives only this local directory; remote registries and remote rule URLs are not configured.

OSV online mode can transmit package identifiers and versions to OSV.dev and deps.dev. Offline mode uses the scanner's pre-provisioned database and requires a declared `VIBESEC_OSV_DATABASE_DATE`; VibeSec does not fetch or refresh it. Checkov is offline at runtime. Syft enrichment and update checks are disabled. Trivy vulnerability databases may still require normal scanner database access unless separately cached; private-registry credentials are not configured by the starter.

## Future evaluation

ZAP, fuzzing, SLSA, and OSSF Scorecard remain unimplemented. Before adoption, maintainers must verify current licenses, maintenance, required services, data transmission, rule licenses, release integrity, and overlap. Research notes are inputs, not authority.
