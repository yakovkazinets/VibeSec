# Final independent v1 pre-release review

The independent review examined `main` at
`f19d5dcf29dc13b6b716d39bf11da1e31ca94234` on 2026-07-25. Verified fixes are
isolated on `fix/v1-final-review`. This record does not claim that a tag,
release, merge, push, or signed release candidate exists.

## Recommendation

`ready_with_documented_limitations`

No reviewed release blocker remains after the fixes and validation described
below. A clean result is not proof that VibeSec or an application is secure.

## Review scopes

- A — security and trust boundaries
- B — runtime behavior and exit contracts
- C — packaging, migration, and release artifacts
- D — human and machine documentation consistency
- E — tests, CI, platform claims, and maintainability

## Findings and fixes

| ID | Classification | Verified finding | Resolution |
|---|---|---|---|
| V1R-001 | release_blocker | Scanner and policy JSON could accept duplicate keys or non-finite numbers. | Bounded strict parsing now rejects ambiguous input. |
| V1R-002 | release_blocker | Deep repository YAML could escape the documented exit contract through parser recursion. | Event-level depth, document, and node limits fail closed with exit 3. |
| V1R-003 | release_blocker | Lazy block-quote continuations and indented examples could become authoritative skill prose. | These regions are explicitly non-authoritative and fingerprinted by classification. |
| V1R-004 | release_blocker | The root CLI truncated machine JSON and remapped lifecycle exit 4. | Machine output is complete; scanner and lifecycle exit categories remain distinct. |
| V1R-005 | release_blocker | Extension failures could be wrapped in a success envelope. | Envelope status is derived from the exact adapter exit and coverage pair. |
| V1R-006 | release_blocker | Derived finding-group and priority fields were not fully tied to source findings. | Every count, scanner, member, runtime flag, reason, and priority is cross-validated. |
| V1R-007 | release_blocker | Secret-bearing authenticated workflows allowed branch-selected manual dispatch. | Repository workflows and generated authenticated workflows are schedule-only; doctor rejects manual dispatch. |
| V1R-008 | release_blocker | Published profile artifact and coverage-state inventories differed from workflows. | Human, machine, starter-workflow, and regression inventories now agree. |
| V1R-009 | release_blocker | Examples, public flags, and implementation-status statements contained stale or invalid claims. | All eleven examples now execute against harmless prerequisites, and generated references expose the frozen flags and artifacts. |
| V1R-010 | release_blocker | Provenance emitted four subjects while its schema and documentation required three. | Runtime, schema, verification, tests, and documentation now require the same four subjects. |
| V1R-011 | release_blocker | The manifest claimed CycloneDX 1.7 while actual Syft output is 1.6. | CycloneDX 1.6 and SPDX 2.3 are enforced exactly throughout the release contract. |
| V1R-012 | release_blocker | Migration records were metadata-only. | All eleven representative installations now run the real read-only planner and verify preservation by whole-tree digest. |
| V1R-013 | release_blocker | Release readiness could reuse a stale test total. | The release workflow reruns the full suite and validator for the exact SHA and accepts only fresh commit-bound evidence. |
| V1R-014 | release_blocker | The committed readiness record was stale and could be mistaken for a self-referential current-commit assertion. | It is now an explicit historical snapshot of the reviewed main SHA. |
| V1R-015 | high | API-fuzzing integration was missing from workflow inventory regression coverage. | The workflow is now included and its optional, unprivileged trigger contract is tested. |

## Validation

- Reviewed main: 406 automated tests passed, with 2 filesystem-specific skips.
- Final fix worktree: 430 automated tests passed, with 2 platform-specific skips.
- All 18 required CI job-equivalent matrices passed locally or used the closest
  controlled equivalent where the platform could not run the real tool.
- All 11 representative migrations and all 11 adoption examples executed.
- Repository, generated-document, link, anchor, skill, JSON, YAML, TOML,
  Python, shell, Opengrep-rule, and actionlint validation passed.
- Bundle build, byte comparison, verification, initializer, installation
  verification, doctor, and upgrade-plan checks passed.
- Unsigned release structure, checksums, exact CycloneDX 1.6, exact SPDX 2.3,
  four-subject provenance, manifest, readiness, and tampering checks passed.

The deterministic unsigned development consumer bundle used `source_commit:
null`, contained 204 files, was 378,530 bytes, and had SHA-256
`8d831d3389fbf02b795abfd484a818711cb1aef06bc65aa1a32b75f0734cd470`.
Two independent builds were byte-identical and the bundle verifier accepted it.

## Accepted limitations and deferred work

- Complete native Minimal and Standard scanning is validated on Linux x86_64;
  the other cataloged platforms remain conditional or experimental.
- Docker was unavailable on the macOS arm64 review host. Live Checkov, ZAP,
  Schemathesis, and container-target claims require their exact GitHub
  integration workflows.
- GitHub OIDC identity and signed candidate verification require
  `.github/workflows/release-candidate.yml`; only the unsigned structural path
  was exercised locally.
- ShellCheck was unavailable. Bash syntax validation and actionlint workflow
  linting passed independently.
- Explicit download-byte ceilings and fully streaming archive-member limits
  remain deferred availability hardening. Archive integrity, traversal, link,
  device, collision, mode, and manifest checks remain enforced.
- Installed extensions and external agent behavior remain maintainer trust
  decisions. A complete CommonMark model beyond the documented structural
  classification also remains deferred.

The apparent duplicate workflow timeout observed during review was overlapping
inspection output, not duplicate YAML. Archive duplicate-member wording was
also narrowed to match the implemented executable-target and manifest checks.

## GitHub-only completion gates

After this branch is pushed and reviewed, `.github/workflows/ci.yml` must
provide the sole required aggregate status named exactly `validate` for the
branch changes. A release operator must then use
`.github/workflows/release-candidate.yml` from `main` to exercise Linux
real-scanner installation, Docker where applicable, and GitHub OIDC signing for
the exact source SHA. No tag or release was created by this review.

The synchronized machine record is
[`machine/v1-final-review.json`](../machine/v1-final-review.json).
