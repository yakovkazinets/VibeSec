# Architecture

## Goals

VibeSec provides a maintainable, open-source starting point for developers without dedicated security staff: a repository-aware coding-agent skill and copyable Minimal and Standard GitHub Actions profiles. It prioritizes explicit evidence, safe defaults, small changes, and useful local artifacts.

VibeSec does not replace threat modeling, code review, penetration testing, incident response, or professional judgment. It does not guarantee that an application is secure.

## Non-goals

Neither profile executes application builds, test suites, package lifecycle scripts, Dockerfiles, or deployment code. The Standard profile executes a pinned Checkov scanner container, not a target application container. VibeSec does not provide runtime, business-logic, authorization, cloud-account, production-configuration, or DAST assurance. It is not a vulnerability-management service and does not automatically remediate, suppress, merge, or deploy changes.

## Components and order

The minimal profile installs checksum-verified release binaries, runs Trivy, Gitleaks, and actionlint, normalizes their output, applies baseline and suppression policy, writes JSON and Markdown reports, then retains only those normalized reports. Installation precedes scanning so an unverified binary cannot influence results. Normalization precedes policy so tool-specific formats cannot silently change enforcement. Raw scanner output stays runner-local because it may contain discovered secret material. Artifact upload runs even after failure so maintainers can distinguish findings from broken tooling.

The imported-skill validator is a separate passive component. It bounds the package, decodes strict UTF-8, canonicalizes LF and Unicode NFC, rejects ambiguous YAML and Markdown structures, validates local references inside a canonical skill root, and hashes normalized content. Validation precedes interpretation so parser-confusion data cannot gain authority while its structure is still disputed. The validator never executes scripts, installs packages, follows external links, reads secrets, or treats body text as governing instructions.

Trivy provides broad filesystem dependency, secret, and configuration coverage. Gitleaks provides a dedicated second view of secrets. actionlint validates GitHub Actions syntax and common expression problems. Repository-aware selection matters because irrelevant scanners add noise, runtime, and maintenance without adding meaningful coverage.

`.github/workflows/ci.yml` protects VibeSec itself. The consumer starters require the accompanying local support directories and never download mutable VibeSec code at runtime. The Standard starter separates code under test from code controlling the scan: it archives `scripts/`, `config/`, `policy/`, and `rules/` from the pull request base commit into a runner-temporary trusted harness, installs tools there, scans the checked-out tree, and writes reports to another runner-temporary directory. Push, schedule, and manual runs use their current trusted commit. VibeSec's own CI instead executes proposed implementation changes so they can be tested, but uses read-only permissions and no secrets.

## Standard profile pipeline

`detect_repository.py` inventories supported languages, manifests, lockfiles, Dockerfiles, CI configuration, and content-aware multi-document IaC markers in stable path order. Traversal does not follow symlinks and fails closed at explicit file and depth limits. That inventory routes scanners; a skipped category is never described as clean. `run_standard_profile.py` records exactly one of `ran`, `not_applicable`, `not_configured`, or `tool_error` for every Standard component in `coverage.json`, including relevant inputs, output paths, network behavior, and whether application code executed, then appends a sanitized coverage table and explicit limitations to `report.md`.

Each scanner receives an explicit trusted config or ignore path so target-controlled `.gitleaks.toml`, `.semgrepignore`, actionlint, Syft, Trivy, Checkov, and OSV configuration cannot reduce coverage. Opengrep scans supported first-party source with only the trusted `rules/opengrep/` pack. OSV-Scanner v2 scans source manifests without fix mode, call analysis, transitive resolution, builds, or project installation. Offline mode requires a fresh, structurally validated caller-provisioned database directory and passes that path explicitly. Syft scans `dir:.` with a relative base path and creates CycloneDX JSON and SPDX JSON with enrichment, remote metadata, and update checks disabled; VibeSec removes the absolute checkout prefix before requiring both artifacts to be structurally valid and nonempty. Checkov runs only after IaC detection, in an immutable official container with a read-only repository mount, no network, no capabilities, no target config, and no external modules. Trivy covers filesystem secrets and configuration, while an optional separate image scan accepts only a prebuilt digest reference and is disabled on pull requests and unknown GitHub event types.

Raw outputs stay runner-local under `results/raw/`. Bounded normalizers retain identifiers, locations, severity, and short descriptions but discard snippets and secret values. Malformed scanner output exits `3`; scanner execution failure exits `2`; findings remain distinct and are evaluated against `policy/standard-baseline.json`. Minimal behavior and `policy/baseline.json` remain unchanged.

## Trigger behavior

| Trigger | Minimal-profile behavior | Standard-profile difference | Reason |
|---|---|---|---|
| Pull request | Scan the checked-out repository with read-only permissions and no secrets | Add detected Standard scopes; image scan is forcibly `not_configured` | Give early feedback without granting untrusted forks privileged context |
| Push to `main` | Repeat the same scan on accepted default-branch content | Add detected Standard scopes; no image unless explicitly configured | Confirm the integrated state and retain an auditable report |
| Weekly schedule | Rescan unchanged content against updated vulnerability data | Add detected Standard scopes and record network/database mode | Detect newly disclosed vulnerabilities without requiring a code change |
| Manual dispatch | Run the same profile on demand | May accept an already-built immutable image digest | Support maintenance and trusted optional image scanning without changing workflow code |

Every trigger starts in observation mode. After maintainers review historical findings, they may record the reviewed baseline and select `new` enforcement. The order matters: enforcing unknown historical debt first often causes teams to disable the workflow rather than adopt it safely.

## Planned, not implemented

ZAP, fuzzing, SLSA provenance, and OSSF Scorecard remain future profile candidates. None is executed or implied by either current profile.

A complete skill package manager, archive ingestion, automatic external installation, cross-agent execution, and imported-script execution are also outside v0.1.
