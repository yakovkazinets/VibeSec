# Changelog

All notable changes will be documented here. The project follows semantic versioning after its first tagged release.

## Unreleased

### Added

- Repository governance and security documentation.
- Minimal Trivy, Gitleaks, and actionlint profile.
- Shared normalization, baseline, suppression, and policy-gate model.
- Repository-aware `appsec-guardian` coding-agent skill.
- Human-readable escaped finding reports and strict shared-result validation.
- Static repository configuration validation and explicit actionlint coverage for the starter workflow.
- Fail-closed imported-skill validation with canonical UTF-8/NFC/LF fingerprints and contained reference hashing.
- Parser-confusion regression fixtures covering YAML, Markdown, Unicode, path, symlink, and size boundaries.

Planned Standard and Advanced profile features are not implemented.
