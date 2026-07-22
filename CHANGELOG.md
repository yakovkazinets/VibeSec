# Changelog

All notable changes will be documented here. The project follows semantic versioning after its first tagged release.

## Unreleased

### Added

- Strict machine-readable security capability accountability matrix with generated human documentation.
- Positive and negative fixtures for every current scanner family and internal coverage, policy, inventory, baseline, and trusted-harness capability.
- Minimal and Standard repository self-scans, exact coverage assertions, sanitized artifact validation, and controlled scanner-failure evidence in CI.
- Five-minute Quick Start, profile-selection guide, compatibility matrix, complete environment-variable reference, upgrade guide, and sanitized sample reports.
- Dry-run-first consumer initializer with conflict refusal, atomic creation, staged Standard bootstrap, installation manifests, and read-only preflight diagnostics.
- Deterministic consumer fixtures and copy-and-adopt tests for Minimal, Standard, forks, monorepositories, unsupported repositories, overlaps, conflicts, and symlink boundaries.
- Canonical `VERSION` parsing, deterministic consumer-only ZIP construction, strict in-memory verification, and verified-bundle initialization.
- Read-only installation verification, offline doctor diagnostics, and non-destructive upgrade planning with stable JSON envelopes and exit codes.

### Changed

- Security-sensitive contribution guidance now requires matrix, fixture, failure-path, artifact, privacy, and trust-boundary updates.
- Restructured README and AppSec Guardian guidance around profile fit, installation state, overlap detection, privacy, and unsupported coverage.
- Expanded installation manifests with source, version, expected hash, and expected mode metadata while retaining bounded legacy inspection.

### Fixed

- Checkov 3.3.8 self-scans now use a trusted empty YAML mapping instead of the invalid empty `/dev/null` document, retain exact failure evidence in CI, and exercise the pinned isolated container against positive and negative fixtures.
- Standard self-scans now use deterministic Actionlint JSON diagnostics, disable target-controlled Opengrep ignore files with supported pinned-version flags, and emit bounded safe component diagnostics on failure.
- Consumer workflows and required support files are now validated as version-compatible installation sets rather than relying on broad manual directory copies.

### Security

- Target-controlled capability expectations, scanner configuration, rules, scripts, policy, and schemas are regression-tested as non-authoritative scan data.
- Fixture guards reject usable-looking credentials; normalized and uploaded evidence rejects raw fake markers and host paths.
- Initializer rejects overwrite, traversal, symlink escape, Unicode/case collisions, partial writes, and self-installation without invoking Git, package managers, network access, or application code.
- Preflight and troubleshooting preserve fork, base-harness, malformed-output, baseline-separation, and no-raw-upload boundaries from v0.2.0.
- Bundle verification fails closed on archive bombs, ambiguous paths and JSON, special files, unexpected modes, and manifest/catalog mismatch before initialization can plan writes.

### Documentation

- Documented coverage-state semantics, network calls, SBOM sensitivity, staged Standard adoption, clean removal, rollback, and explicit compatibility limits.
- Documented unsigned offline distribution, installation statuses, safe doctor diagnostics, and preservation-aware upgrade review.

## 0.2.0 - 2026-07-21

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
