# Self-hosted security validation

VibeSec scans its own repository so advertised controls have current execution evidence. This is separate from implementation unit tests: unit tests verify code branches with controlled fake scanners, scanner accountability validates maintained positive/negative fixtures and normalization, and repository self-scans run the pinned profiles over VibeSec itself.

## Enforced scanners and expected states

The Minimal self-scan expects Trivy filesystem, Gitleaks, and actionlint to be `ran`. The Standard self-scan expects Opengrep, OSV-Scanner, Syft, Checkov, Trivy filesystem, Gitleaks, and actionlint to be `ran`. The repository deliberately contains harmless Terraform and workflow fixtures, so Checkov is applicable. Prebuilt-image scanning is `not_configured`: no arbitrary public image is supplied, and fork-like events remain unable to enable it.

Controlled fixture evidence covers exact findings for Trivy, Gitleaks, actionlint, all four Opengrep rules, OSV, Checkov, and image normalization. Syft fixtures assert one synthetic package in CycloneDX and SPDX. Internal fixtures assert inventory, all four coverage states, result/policy distinctions, profile-specific baselines, and trusted-harness replacement resistance. See the [capability matrix](security-capability-matrix.md) for IDs and enforcement references.

## Artifacts and privacy

Minimal artifacts are `normalized.json`, `report.md`, `coverage.json`, and `policy-result.json`. Standard adds `inventory.json`, `sbom.cyclonedx.json`, and `sbom.spdx.json`. Validators require supported schemas, repository-relative paths, current profile identity, exact coverage, no stale SBOM, no raw fake-secret marker, and no runner/home/temp path. Raw scanner documents are not uploaded and optional SBOMs remain separable from mandatory reports.

Tool installation downloads checksum-verified releases; Opengrep additionally uses Sigstore identity verification. Trivy may obtain its scanner database. Standard online OSV can send package identifiers, versions, ecosystems, and file hashes; offline mode requires caller-provisioned validated data. Opengrep, Gitleaks, actionlint, Syft, and local normalization do not upload source. Checkov uses its immutable container with the repository read-only and container networking disabled. Image scanning remains digest-only and trusted-event-only.

The fake marker `VIBESEC_FAKE_SECRET_DO_NOT_USE_000000000000` is intentionally outside live provider formats and cannot authenticate. A repository guard rejects common live credential formats in the fixture tree.

## Investigation and updates

If a positive finding disappears, identify the capability ID, confirm the pinned scanner and trusted configuration, reproduce only that tiny fixture, compare normalized fields, and treat unexplained disappearance as a regression. If a negative fixture gains a finding, review whether the scanner improved, the fixture became ambiguous, or a false positive was introduced; do not loosen the expectation without documented review.

Tool failures must remain `tool_error`, preserve mandatory diagnostic artifacts, remove stale output, and block a clean claim. A scanner-version update follows the procedure in the [security validation policy](security-validation-policy.md) and contribution guide. New capabilities require matrix data, both fixtures, expected metadata, failure and trust tests, artifact validation, limitations, and a mandatory CI reference.

The Standard harness emits one bounded diagnostic line for execution or structural failures: component, failure category, a harness-controlled reason, a repository-relative artifact pointer, and this document. It never echoes raw scanner output, snippets, environment values, credentials, or absolute runner paths.

The stable CI jobs are `self-scan-minimal`, `self-scan-standard`, `scanner-accountability`, and `security-artifacts`. The existing required `validate` job depends on all four, so a ruleset that already requires `validate` remains merge-blocking without an immediate ruleset migration. Projects may additionally require the individual names for clearer branch-protection reporting.

A passing self-scan demonstrates only that the pinned controls completed with expected evidence. It does not prove VibeSec is secure.
