# VibeSec v1 interface reference

This file is generated from strict JSON under [`machine/`](../machine/). Do not edit generated tables by hand.

## Public interface inventory

<!-- BEGIN GENERATED V1 REFERENCE -->
| Stable ID | Status | Owner | Summary |
|---|---|---|---|
| `vibesec.agents.contract` | `stable` | multi-agent support | Agent contract, adapters, capabilities, safety rules, and task-pack identifiers. |
| `vibesec.artifacts.security` | `stable` | profile orchestration | Sanitized scan artifacts and their publication boundary. |
| `vibesec.capabilities.registry` | `stable` | capability model | The versioned project questionnaire and security-capability evidence registry. |
| `vibesec.cli.agents` | `stable` | agent guidance manager | Manage deterministic, non-executing guidance for supported coding agents. |
| `vibesec.cli.doctor` | `stable` | installation doctor | Diagnose an installed VibeSec profile without changing it. |
| `vibesec.cli.extensions` | `stable` | extension manager | List, verify, describe, install, disable, enable, remove, plan, and run verified local extensions. |
| `vibesec.cli.init` | `stable` | initializer | Preview or initialize a profile or add-on from source or a verified bundle. |
| `vibesec.cli.scan` | `stable` | portable CLI | Run the Minimal or Standard profile against a local repository. |
| `vibesec.cli.upgrade-plan` | `stable` | upgrade planner | Produce a deterministic, non-mutating installation upgrade plan. |
| `vibesec.cli.verify` | `stable` | installation verifier | Verify installed files and provenance without changing the target. |
| `vibesec.compatibility.platforms` | `stable` | platform support | Honest host, runner, Docker, Windows, and GHES support claims. |
| `vibesec.configuration.contract` | `stable` | configuration and distribution | Versioned configuration files, environment variables, bundle layout, and strict parser boundary. |
| `vibesec.coverage.states` | `stable` | coverage model | Exact scanner coverage state vocabulary. |
| `vibesec.execution.modes` | `experimental` | portable execution | Native, container, and auto portable-execution selection. |
| `vibesec.extensions.contract` | `stable` | extension platform | Extension manifest, kind, permission, lifecycle, and execution contract. |
| `vibesec.findings.contract` | `stable` | normalization and finding intelligence | Normalized findings, correlation groups, and priority records. |
| `vibesec.policies.contract` | `stable` | policy gate | Observe, new, and all enforcement plus independent profile baselines and suppressions. |
| `vibesec.profiles.api-fuzzing` | `conditionally_enforced` | API fuzzing add-on | Opt-in bounded active API fuzzing and inert injection-marker testing. |
| `vibesec.profiles.api-security-baseline` | `conditionally_enforced` | API security add-on | Opt-in bounded OpenAPI contract testing against an isolated prebuilt API image. |
| `vibesec.profiles.authenticated-security-testing` | `conditionally_enforced` | authenticated testing layer | Optional bearer-authenticated comparison for passive DAST and OpenAPI testing. |
| `vibesec.profiles.dast-baseline` | `conditionally_enforced` | DAST add-on | Opt-in passive ZAP testing of an explicitly supplied prebuilt application image. |
| `vibesec.profiles.minimal` | `stable` | Minimal profile | Source, secret, and workflow linting with Trivy, Gitleaks, and actionlint. |
| `vibesec.profiles.standard` | `stable` | Standard profile | Minimal plus SAST, dependency analysis, SBOM, IaC, optional image scanning, and finding intelligence. |
| `vibesec.release.contract` | `stable` | release candidate pipeline | Deterministic consumer bundle, SBOMs, readiness, manifest, provenance, checksums, and optional OIDC signature bundle. |
| `vibesec.results.lifecycle` | `stable` | distribution lifecycle | Machine-readable doctor, verification, upgrade-plan, and operation envelopes. |
| `vibesec.runtime.exit-codes` | `stable` | shared command runtime | Process exit categories for scanning, distribution, lifecycle, and verification commands. |
| `vibesec.scanners.registry` | `stable` | tool inventory | Pinned scanner and supporting security-tool identities. |
| `vibesec.workflows.contract` | `stable` | GitHub Actions integration | Copyable profile templates, trusted integration workflows, and aggregate CI status. |

## Domain members

### Project

Source: `VERSION`

| Member | Status |
|---|---|
| `vibesec.coverage.states` | `stable` |
| `vibesec.runtime.exit-codes` | `stable` |

### Capabilities

Source: `config/security-capabilities.json`

| Member | Status |
|---|---|
| `api.content-type-conformance` | `conditionally_enforced` |
| `api.negative-data-rejection` | `conditionally_enforced` |
| `api.negative-generation` | `conditionally_enforced` |
| `api.openapi-schema-validation` | `stable` |
| `api.policy-enforcement` | `stable` |
| `api.positive-data-acceptance` | `conditionally_enforced` |
| `api.positive-generation` | `conditionally_enforced` |
| `api.response-schema-conformance` | `conditionally_enforced` |
| `api.result-normalization` | `stable` |
| `api.server-error-detection` | `conditionally_enforced` |
| `api.status-code-conformance` | `conditionally_enforced` |
| `api.tool-failure-handling` | `stable` |
| `api.trusted-event-isolation` | `stable` |
| `authenticated.bearer-configuration-validation` | `stable` |
| `authenticated.correlation` | `stable` |
| `authenticated.evidence` | `stable` |
| `authenticated.missing-secret-handling` | `stable` |
| `authenticated.openapi-testing` | `conditionally_enforced` |
| `authenticated.passive-dast` | `conditionally_enforced` |
| `authenticated.scanner-step-secret-scoping` | `stable` |
| `authenticated.secret-redaction` | `stable` |
| `authenticated.tool-failure-handling` | `stable` |
| `dast.artifact-sanitization` | `stable` |
| `dast.cleanup` | `stable` |
| `dast.failure-paths` | `stable` |
| `dast.isolated-runtime` | `stable` |
| `dast.normalization` | `stable` |
| `dast.policy-gate` | `stable` |
| `dast.target-validation` | `stable` |
| `dast.trusted-event` | `stable` |
| `dast.zap-passive-baseline` | `conditionally_enforced` |
| `fuzzing.bounded-active-api` | `conditionally_enforced` |
| `minimal.actionlint` | `stable` |
| `minimal.gitleaks` | `stable` |
| `minimal.result-policy` | `stable` |
| `minimal.trivy-filesystem` | `stable` |
| `standard.checkov-iac` | `conditionally_enforced` |
| `standard.coverage-report` | `stable` |
| `standard.finding-intelligence` | `stable` |
| `standard.opengrep-sast` | `stable` |
| `standard.osv-dependencies` | `stable` |
| `standard.profile-baselines` | `stable` |
| `standard.repository-inventory` | `stable` |
| `standard.syft-sbom` | `stable` |
| `standard.trivy-image` | `conditionally_enforced` |
| `standard.trusted-harness` | `stable` |
| `vibesec.capabilities.registry` | `stable` |

### Profiles

Source: `config/adoption-files.json`

| Member | Status |
|---|---|
| `vibesec.profiles.api-fuzzing` | `conditionally_enforced` |
| `vibesec.profiles.api-security-baseline` | `conditionally_enforced` |
| `vibesec.profiles.authenticated-security-testing` | `conditionally_enforced` |
| `vibesec.profiles.dast-baseline` | `conditionally_enforced` |
| `vibesec.profiles.minimal` | `stable` |
| `vibesec.profiles.standard` | `stable` |

### Scanners

Source: `config/tools.json`

| Member | Status |
|---|---|
| `actionlint` | `stable` |
| `checkov` | `conditionally_enforced` |
| `cosign` | `conditionally_enforced` |
| `dast-fixture-python` | `internal` |
| `gitleaks` | `stable` |
| `opengrep` | `stable` |
| `osv-scanner` | `stable` |
| `schemathesis` | `conditionally_enforced` |
| `syft` | `stable` |
| `trivy` | `stable` |
| `vibesec.scanners.registry` | `stable` |
| `zap-baseline` | `conditionally_enforced` |

### Workflows

Source: `config/adoption-files.json`

| Member | Status |
|---|---|
| `.github/workflows/api-fuzzing-integration.yml` | `conditionally_enforced` |
| `.github/workflows/api-security-integration.yml` | `conditionally_enforced` |
| `.github/workflows/authenticated-api-integration.yml` | `conditionally_enforced` |
| `.github/workflows/authenticated-dast-integration.yml` | `conditionally_enforced` |
| `.github/workflows/ci.yml` | `stable` |
| `.github/workflows/dast-integration.yml` | `conditionally_enforced` |
| `.github/workflows/release-candidate.yml` | `conditionally_enforced` |
| `templates/github-actions/api-fuzzing.yml` | `conditionally_enforced` |
| `templates/github-actions/api-security-baseline.yml` | `conditionally_enforced` |
| `templates/github-actions/dast-baseline.yml` | `conditionally_enforced` |
| `templates/github-actions/security-baseline.yml` | `stable` |
| `templates/github-actions/security-standard.yml` | `stable` |
| `vibesec.workflows.contract` | `stable` |

### Cli

Source: `vibesec`

| Member | Status |
|---|---|
| `vibesec.cli.agents` | `stable` |
| `vibesec.cli.doctor` | `stable` |
| `vibesec.cli.extensions` | `stable` |
| `vibesec.cli.init` | `stable` |
| `vibesec.cli.scan` | `stable` |
| `vibesec.cli.upgrade-plan` | `stable` |
| `vibesec.cli.verify` | `stable` |
| `vibesec.execution.modes` | `experimental` |
| `vibesec.results.lifecycle` | `stable` |
| `vibesec.runtime.exit-codes` | `stable` |

### Configuration

Source: `config/environment-variables.json`

| Member | Status |
|---|---|
| `config/adoption-files.json` | `stable` |
| `config/environment-variables.json` | `stable` |
| `config/extension-manifest-schema.json` | `stable` |
| `config/github-actions.json` | `stable` |
| `config/portable-execution.json` | `experimental` |
| `config/security-capabilities.json` | `stable` |
| `config/tools.json` | `stable` |
| `vibesec.configuration.contract` | `stable` |

### Policies

Source: `policy/severity-thresholds.yml`

| Member | Status |
|---|---|
| `policy.baseline.v1` | `stable` |
| `policy.enforcement.all` | `stable` |
| `policy.enforcement.new` | `stable` |
| `policy.enforcement.observe` | `stable` |
| `policy.suppression.v1` | `stable` |
| `vibesec.policies.contract` | `stable` |

### Artifacts

Source: `config/supply-chain-policy.json`

| Member | Status |
|---|---|
| `SHA256SUMS` | `stable` |
| `config/api-fuzzing-result-schema.json` | `stable` |
| `config/api-security-result-schema.json` | `stable` |
| `config/extension-manifest-schema.json` | `stable` |
| `config/finding-groups-schema.json` | `stable` |
| `config/prioritized-findings-schema.json` | `stable` |
| `config/provenance-schema.json` | `stable` |
| `config/release-manifest-schema.json` | `stable` |
| `config/zap-passive-plan-schema.json` | `stable` |
| `coverage.json` | `stable` |
| `finding-groups.json` | `stable` |
| `machine/schemas/agent-adapter.schema.json` | `stable` |
| `machine/schemas/agent-contract.schema.json` | `stable` |
| `machine/schemas/agent-task.schema.json` | `stable` |
| `machine/schemas/domain-catalog.schema.json` | `stable` |
| `machine/schemas/public-interface.schema.json` | `stable` |
| `machine/schemas/release-readiness.schema.json` | `stable` |
| `normalized.json` | `stable` |
| `policy-result.json` | `stable` |
| `prioritized-findings.json` | `stable` |
| `provenance.intoto.jsonl` | `stable` |
| `release-manifest.json` | `stable` |
| `release-readiness.json` | `stable` |
| `report.md` | `stable` |
| `sbom.cyclonedx.json` | `stable` |
| `sbom.spdx.json` | `stable` |
| `vibesec-consumer-bundle.zip` | `stable` |
| `vibesec.artifacts.security` | `stable` |

### Findings

Source: `config/finding-groups-schema.json`

| Member | Status |
|---|---|
| `finding-group.v1` | `stable` |
| `normalized-finding.v1` | `stable` |
| `prioritized-finding.v1` | `stable` |
| `vibesec.findings.contract` | `stable` |

### Extensions

Source: `config/extension-manifest-schema.json`

| Member | Status |
|---|---|
| `extension.kind.scanner` | `stable` |
| `extension.manifest.v1` | `stable` |
| `extension.permissions.v1` | `stable` |
| `vibesec.extensions.contract` | `stable` |

### Agents

Source: `machine/agents/contract.json`

| Member | Status |
|---|---|
| `agent.adapter.claude-code` | `stable` |
| `agent.adapter.codex` | `stable` |
| `agent.adapter.gemini-cli` | `stable` |
| `agent.adapter.kimi-cli` | `stable` |
| `agent.contract.v1` | `stable` |
| `agent.task.add-security-feature` | `stable` |
| `agent.task.fix-security-findings` | `stable` |
| `agent.task.prepare-pull-request` | `stable` |
| `agent.task.prepare-release-candidate` | `stable` |
| `agent.task.resolve-ci-failure` | `stable` |
| `agent.task.resolve-merge-conflicts` | `stable` |
| `agent.task.review-extension` | `stable` |
| `agent.task.security-audit` | `stable` |
| `agent.task.upgrade-vibesec` | `stable` |
| `agent.task.validate-installation` | `stable` |
| `vibesec.agents.contract` | `stable` |

### Release

Source: `config/release-manifest-schema.json`

| Member | Status |
|---|---|
| `release.manifest.v1` | `stable` |
| `release.provenance.v1` | `stable` |
| `release.readiness.v1` | `stable` |
| `release.verification-record.v1` | `stable` |
| `vibesec.release.contract` | `stable` |

### Compatibility

Source: `config/portable-execution.json`

| Member | Status |
|---|---|
| `ghes.limitations` | `experimental` |
| `github-hosted.ubuntu` | `stable` |
| `linux-amd64` | `stable` |
| `linux-arm64` | `conditionally_enforced` |
| `macos-amd64` | `conditionally_enforced` |
| `macos-arm64` | `conditionally_enforced` |
| `self-hosted.runner-2.327.1` | `stable` |
| `vibesec.compatibility.platforms` | `stable` |
| `windows.native` | `internal` |
<!-- END GENERATED V1 REFERENCE -->
