# VibeSec v1 release readiness

The authoritative readiness record is [`machine/release-readiness.json`](../machine/release-readiness.json). It records the reviewed main commit, schema and interface status totals, validation evidence, platform claims, migration and documentation coverage, known limitations, deferred and experimental features, unresolved risks, and release blockers.

`ready_with_known_limitations` means required offline validation and artifact cross-verification passed while explicitly documented limitations remain. It is not a claim that VibeSec or an application is secure. `blocked` requires at least one blocker; a non-blocked report cannot contain blockers.

The manual release-candidate workflow builds the deterministic consumer bundle twice, compares it byte-for-byte, generates local CycloneDX and SPDX SBOMs, generates readiness for the exact main commit, prepares a strict artifact set, signs checksums with the trusted GitHub OIDC identity, verifies every digest and provenance subject, and uploads only the candidate. It does not create a tag, GitHub release, package, release commit, or push.

This branch prepares version metadata under `Unreleased`. It does not publish v1.0.
