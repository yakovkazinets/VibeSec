# VibeSec Guardian v1 release readiness

The committed [`machine/release-readiness.json`](../machine/release-readiness.json)
is a deterministic historical snapshot of the explicitly identified reviewed
commit. It does not claim to describe the later commit that contains the
snapshot itself, and its recorded test total must not be substituted for fresh
candidate validation.

For a release candidate, the manual workflow reruns the complete test suite and
repository validator after checking out the exact requested `main` SHA. A
bounded machine-readable evidence record binds both successful runs and the
fresh test total to that SHA. Candidate readiness accepts only that same-job
evidence and records it as `exact-sha-validate:<SHA>`.

`ready_with_known_limitations` means required offline validation and artifact cross-verification passed while explicitly documented limitations remain. It is not a claim that VibeSec Guardian or an application is secure. `blocked` requires at least one blocker; a non-blocked report cannot contain blockers.

The manual release-candidate workflow then builds the deterministic consumer
bundle twice, compares it byte-for-byte, generates local CycloneDX 1.7 and SPDX
2.3 SBOMs, prepares a strict artifact set, signs checksums with the trusted
GitHub OIDC identity, verifies every digest and all four provenance subjects,
and uploads only the candidate. It does not create a tag, GitHub release,
package, release commit, or push.

This branch prepares v1.1.0 version metadata, managed-runtime evidence, and draft release notes under `Unreleased`. It does not create a tag or publish v1.1.0.
