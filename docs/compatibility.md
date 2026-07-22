# Compatibility matrix

Status meanings: **tested** has an automated fixture; **supported but not fully exercised** is routed by current code but lacks an end-to-end real-tool fixture; **detected only** influences inventory/coverage but has no dedicated semantic scanner claim; **not supported** is outside deterministic routing. Application code is never executed.

## Languages

| Language | Evidence | Standard scanner | Status | Network | Limitations |
|---|---|---|---|---|---|
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | Opengrep local JS rules | tested | none for source scan | narrow high-confidence starter rules |
| TypeScript | `.ts`, `.tsx` | Opengrep local JS/TS rules | supported but not fully exercised | none | same narrow rules; no type-aware build |
| Python | `.py` | Opengrep local Python rules | tested | none | no import/runtime analysis |
| Java | `.java` | Opengrep local Java rules | tested | none | no build/classpath analysis |
| Go | `.go` | Opengrep local Go rules | tested | none | OSV call analysis disabled |

Minimal does not use this language router; Trivy support depends on the pinned scanner. Other languages are not supported by VibeSec-owned SAST rules.

## Package ecosystems

| Ecosystem | Evidence currently detected | Scanner/profile | Status | Network | Limitations |
|---|---|---|---|---|---|
| npm | `package.json`, `package-lock.json`, `npm-shrinkwrap.json` | OSV + Syft / Standard | tested | OSV online advisory queries | no package installation or lock regeneration |
| Yarn | `yarn.lock` | OSV + Syft / Standard | supported but not fully exercised | same | workspace edge cases may vary by scanner |
| pnpm | `pnpm-lock.yaml` | OSV + Syft / Standard | supported but not fully exercised | same | no workspace command execution |
| pip/requirements | `requirements*.txt`, `pyproject.toml` | OSV + Syft / Standard | tested | same | unpinned requirements reduce precision |
| Poetry | `poetry.lock`, `pyproject.toml` | OSV + Syft / Standard | supported but not fully exercised | same | no Poetry execution |
| Pipenv | `Pipfile.lock` | OSV + Syft / Standard | supported but not fully exercised | same | no Pipenv execution |
| Maven | `pom.xml` | OSV + Syft / Standard | tested detection | same | no effective-POM/build resolution |
| Gradle | `build.gradle`, `build.gradle.kts`, `gradle.lockfile` | OSV + Syft / Standard | tested detection | same | no Gradle execution |
| Go modules | `go.mod`, `go.sum` | OSV + Syft / Standard | tested | same | call analysis and resolution disabled |

The detector also recognizes Bun and uv evidence, but those combinations are **detected only** in v0.2.1 and are not claimed as fully supported. Minimal uses Trivy's own filesystem package support rather than this routing table.

## Infrastructure and repository artifacts

| Artifact | Detection evidence | Scanner/profile | Status | Network | Limitations |
|---|---|---|---|---|---|
| Terraform/OpenTofu | `.tf` | Checkov + Trivy / Standard | tested | Checkov none | syntax is not executed; OpenTofu shares Terraform evidence |
| Kubernetes | YAML/JSON mapping with `apiVersion` and `kind` | Checkov + Trivy / Standard | tested | none | bounded files only; templated output may be missed |
| Helm | valid `Chart.yaml` with name/version/API | Checkov + Trivy / Standard | supported but not fully exercised | none | templates are not rendered |
| Kustomize | `kustomization.y*ml` with resource/base/component list | Checkov + Trivy / Standard | supported but not fully exercised | none | overlays are not built |
| CloudFormation | template version plus `Resources` mapping | Checkov + Trivy / Standard | supported but not fully exercised | none | transforms are not resolved |
| AWS SAM | CloudFormation-shaped SAM template | same | detected only | none | no dedicated SAM classification |
| Bicep | `.bicep` | Checkov + Trivy / Standard | supported but not fully exercised | none | no compilation |
| ARM | deployment-template `$schema` in YAML/JSON | Checkov + Trivy / Standard | supported but not fully exercised | none | linked templates are not fetched |
| Dockerfiles | `Dockerfile` or `Dockerfile.*` | Trivy config; optional image scan / Standard | tested | image registry only on trusted event | Dockerfile is never built; tag-only images rejected |
| GitHub Actions | `.github/workflows/*.y*ml` | actionlint + Trivy / both | tested | none for lint | other workflow directories are not treated as GitHub Actions |

Checkov requires an available Docker runtime only when supported IaC is detected. It uses an immutable image, read-only source, no capabilities, and no network. Symlinks, `.git`, `node_modules`, `vendor`, generated/build directories, and other documented skip directories are not traversed. Traversal is bounded at 100,000 inspectable files and depth 40; exceeding a bound fails closed.

## Forks, monorepositories, and unsupported repositories

Fork pull requests receive `contents: read`, no secrets, no private-registry access, and no image scan. Standard obtains scripts/config/policy/rules from the base commit. Monorepositories retain repository-relative evidence for multiple manifest roots; one ecosystem does not suppress another. Unsupported, empty, Markdown-only, and binary-only repositories produce `not_applicable`/outside-coverage statements, never a claim of comprehensive cleanliness.
