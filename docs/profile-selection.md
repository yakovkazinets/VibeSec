# Choosing Minimal or Standard

The Passive DAST Baseline is an independent add-on, not a profile-selection criterion. Add it only when an owner can supply an authorized non-production digest-pinned non-root image and operate a disposable trusted Docker runner. Its passive crawl does not replace SAST, SCA, IaC review, threat modeling, or penetration testing. Static-bearer authenticated coverage is a separate capability layered onto an eligible DAST or API target, not a base profile.

More scanners are not automatically better. Choose the smallest profile that adds useful, maintainable coverage beyond controls already present.

Profile selection and project capabilities are separate decisions. Complete the `[Y/n]` questionnaire first. Explicit No answers prevent inapplicable scanners from running even when filename heuristics suggest otherwise; detection can narrow but never override the manifest. Secrets scanning remains broadly applicable. See [project capabilities](project-capabilities.md).

| Decision area | Minimal | Standard |
|---|---|---|
| Scanners | Trivy filesystem, Gitleaks, actionlint | Opengrep local rules, OSV-Scanner, Syft, conditional Checkov, Trivy secrets/configuration and optional image, Gitleaks, actionlint |
| Typical hosted runtime | About 5–15 minutes; runner/cache dependent | About 10–30 minutes; inventory and ecosystems strongly affect it |
| Required reports | normalized JSON, Markdown | normalized JSON, coverage JSON, inventory JSON, Markdown |
| Optional artifacts | none | validated CycloneDX and SPDX SBOM pair |
| Network | pinned tool downloads; Trivy scanner-managed database access | pinned tool downloads; OSV advisory queries by default; optional registry access; offline OSV supported |
| Review burden | lower; broad scanner results can still need triage | higher; SAST, dependencies, IaC, coverage gaps, and SBOM privacy need ownership |
| Repository prerequisite | Git repository and Linux x86_64 GitHub runner | same, plus two-stage trusted-harness bootstrap; Docker only when IaC invokes Checkov |
| Languages | scanner-dependent broad filesystem checks | explicitly routed JS/TS, Python, Java, and Go source rules |
| Packages | Trivy-supported filesystem evidence | npm/Yarn/pnpm, Python, Maven/Gradle, and Go evidence currently detected; see compatibility |
| IaC | Trivy misconfiguration scan | deterministic IaC detection plus isolated Checkov and Trivy configuration scan |
| Image | no dedicated prebuilt-image input | optional immutable digest, trusted events only; never builds Dockerfiles |
| Fork PR | read-only, no secrets | read-only, no secrets; trusted base harness; image/private-registry access disabled |
| Best fit | solo developer or small team wanting a fast first baseline | team needing source/dependency/SBOM/IaC depth and able to maintain it |
| Main gaps | no explicit coverage inventory or SBOM; broad dependency behavior | narrow VibeSec SAST rules; no builds, runtime, DAST, fuzzing, or business-logic analysis |

## Deterministic recommendation

Choose Minimal when the user wants a fast baseline, has little security experience, lacks ownership for multiple report types, or already has equivalent SAST/SCA/IaC coverage. Choose Standard when the repository contains supported source, dependency, or IaC evidence and the team explicitly needs deeper routing, SBOM output, or coverage-state reporting.

Do not choose Standard merely because more tools sound safer. Inventory existing CodeQL/Semgrep/Snyk or equivalent SAST, Dependabot/Renovate/OSV or equivalent dependency analysis, IaC scanners, secret scanners, and SBOM generation first. Retain existing controls unless a reviewed comparison shows a concrete gap or independent data source worth its maintenance and false-positive cost.

If the repository is unsupported or mostly generated/vendored content, neither profile can establish broad security. Standard provides clearer `not_applicable` and outside-coverage reporting, but that visibility is not itself new scanning coverage.

API Security Baseline is not a third base profile. Consider it only when the manifest declares an API and container image, a reviewed local OpenAPI 3.x contract exists, and an immutable non-root disposable target can run on manual/scheduled events. It sends invalid inputs by design; keep safe-method mode unless mutation is explicitly authorized. Bearer mode tests one static identity only and does not replace role-based authorization, passive DAST, SAST, SCA, or design review.
