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
- Opt-in Standard profile with repository inventory, explicit coverage states, VibeSec-owned Opengrep SAST rules, OSV-Scanner v2, Syft CycloneDX/SPDX SBOMs, conditional Checkov, and trusted-event prebuilt-image scanning.
- Standard-profile normalization, baseline separation, bounded parser validation, safe fake-scanner integration tests, and a copyable least-privilege workflow.

### Security

- Hardened release archive extraction and staged scanner installation; recorded a 2026-07-21 verification date for every supply-chain pin.
- Separated pull-request scan targets from a base-revision trusted harness and explicit scanner configuration, policy, rules, ignore files, tool storage, and results.
- Added bounded repository detection, explicit offline OSV database integrity/freshness checks, richer coverage provenance, stricter result normalization, and stale-output removal.
