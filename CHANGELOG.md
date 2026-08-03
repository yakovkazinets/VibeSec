# Changelog

## Unreleased

- Prepare `1.1.0-dev` for the v1.1.0 release with skill-driven real Minimal and Standard scans, a verified versioned consumer runtime bootstrap, persistent user-level tool/result caches, and explicit separation between assessment, local scanning, and CI adoption.
- Add exact platform-aware native scanner assets for Linux x86_64, macOS arm64, and macOS x86_64; portable Python SHA-256 verification; safe staged extraction; atomic publication; complete cache revalidation; and Opengrep Sigstore identity verification.
- Add managed `vibesec scan --install-tools` routing, outside-repository results, private temporary raw scanner output, complete exit-category preservation, offline tests, and draft v1.1.0 release/upgrade documentation.
- Prepare `1.0.0-dev` with a strict public-interface inventory, v1 stability and support policy, complete human/machine documentation map, documentation drift enforcement, representative migration records, parser and security review, and exact-commit release readiness.
- Add a canonical vendor-neutral agent guidance contract, deterministic Codex, Claude Code, Gemini CLI, and Kimi Code CLI adapters, capability-aware task packs, dry-run-first lifecycle management, digest inventory, offline doctor and verification, threat-model fixtures, and mandatory CI accountability.
- Add a portable local `vibesec` CLI, deterministic native/container/auto selection, an explicit Linux/macOS support matrix, and fail-closed reporting for unavailable complete profile modes.
- Add strict local-only scanner extensions with versioned manifests, namespaced capabilities, restricted permissions, atomic dry-run-first lifecycle management, digest inventories, subprocess adapters, bounded artifacts/diagnostics, a harmless reference extension, and extension-aware distribution and accountability.
- Add bounded opt-in API fuzzing and injection-oriented testing with strict capability dependencies, deterministic Schemathesis orchestration, reviewed inert payloads, isolated runtime controls, separate policy and artifacts, consumer adoption, accountability, and manual live integration.
- Add strict release manifests, deterministic checksums, SLSA-aligned provenance, SBOM linkage, keyless Cosign signing preparation, offline posture validation, a manual trusted release-candidate workflow, consumer verification guidance, and tampering accountability without publishing a release.
- Expand framework-aware Opengrep coverage for Express, Next.js, React, Flask, Django, FastAPI, and Spring with exact positive/negative fixture accountability.
- Add deterministic finding grouping, provenance, explainable priority, optional backward-compatible group policy, schemas, reports, and consumer lifecycle support.
- Require full reviewed evidence agreement for same-scanner fingerprint deduplication, account for all 32 Opengrep rules, and publish validated finding-intelligence artifacts for every DAST/API state.
- Add opt-in static-bearer authenticated DAST and OpenAPI testing with scanner-step-only GitHub secret scoping, stdin delivery, tmpfs raw evidence, in-memory redaction, narrow authenticated/unauthenticated correlation, controlled fixtures, lifecycle validation, and separate live accountability workflows.
- Add the separate opt-in OpenAPI API Security Baseline with immutable Schemathesis 4.24.2, strict schema validation, internal-only container isolation, safe-method defaults, bounded structured normalization, independent policy, controlled fixtures, consumer lifecycle support, and mandatory artifact validation.
- Modernize every supplied GitHub Actions reference to reviewed full-SHA Node 24 releases, add a strict offline action inventory, and preserve checkout credential and artifact-upload boundaries.
- Require Actions Runner 2.327.1 or newer for self-hosted workflows; document GitHub.com/GHES differences, Node 20 non-support, and Node 26 as a future compatibility target.
- Add a separate opt-in passive OWASP ZAP Baseline add-on with immutable non-root target validation, internal Docker isolation, strict normalization, independent policy, sanitized artifacts, accountability fixtures, consumer installation, documentation, and a manual starter workflow.
- Add a strict project-capability questionnaire and manifest with Yes-by-default interactive answers, explicit non-interactive input, manifest-driven scanner applicability, preservation-aware upgrades, and VibeSec Guardian DAST reported as `not_applicable`.

All notable changes are documented here. The project follows semantic versioning; every item above and below this sentence remains part of the single Unreleased section until a release is explicitly published.

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

- Rename the public product display name to VibeSec Guardian and adopt the positioning line “Open-source security for vibe-coded and AI-built software.” Stable `vibesec` commands, namespaces, identifiers, artifact names, update channels, and the `yakovkazinets/VibeSec` repository identity remain unchanged.
- Security-sensitive contribution guidance now requires matrix, fixture, failure-path, artifact, privacy, and trust-boundary updates.
- Restructured README and AppSec Guardian guidance around profile fit, installation state, overlap detection, privacy, and unsupported coverage.
- Expanded installation manifests with source, version, expected hash, and expected mode metadata while retaining bounded legacy inspection.

### Fixed

- Final v1 review now fails closed on ambiguous scanner, policy, SBOM, and repository JSON; bounds deep repository YAML; and keeps lazy quotes, indented code, and examples non-authoritative.
- Portable CLI and extension envelopes now preserve complete machine output and exact scanner versus lifecycle failure categories; finding-intelligence documents are tied back to their source evidence.
- Authenticated secret-bearing workflows are schedule-only, profile artifact inventories match starter workflows, and API-fuzzing workflow coverage is explicit.
- Provenance, CycloneDX 1.7, SPDX 2.3, exact-source readiness evidence, all eleven migrations, and all eleven adoption examples now have aligned executable contracts.
- Standard self-scans now accept the CycloneDX 1.7 document emitted by pinned Syft 1.49.0, preserve both validated SBOMs, and keep Syft process failures distinct from malformed artifacts.
- Standard self-scan image expectations are now derived from trusted event context and product-view applicability, preventing pull-request and post-merge `push` states from being conflated.
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
- Opt-in Standard profile with repository inventory, explicit coverage states, VibeSec Guardian-owned Opengrep SAST rules, OSV-Scanner v2, Syft CycloneDX/SPDX SBOMs, conditional Checkov, and trusted-event prebuilt-image scanning.
- Standard-profile normalization, baseline separation, bounded parser validation, safe fake-scanner integration tests, and a copyable least-privilege workflow.

### Security

- Hardened release archive extraction and staged scanner installation; recorded a 2026-07-21 verification date for every supply-chain pin.
- Separated pull-request scan targets from a base-revision trusted harness and explicit scanner configuration, policy, rules, ignore files, tool storage, and results.
- Added bounded repository detection, explicit offline OSV database integrity/freshness checks, richer coverage provenance, stricter result normalization, and stale-output removal.
