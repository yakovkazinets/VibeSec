# VibeSec v1 interface reference

This file is generated from strict JSON under [`machine/`](../machine/). Do not edit generated tables by hand.

## Public interface inventory

<!-- BEGIN GENERATED V1 REFERENCE -->
| Stable ID | Status | Owner | Summary | Configuration and flags | Artifacts | Coverage states | Exit behavior |
|---|---|---|---|---|---|---|---|
| `vibesec.agents.contract` | `stable` | multi-agent support | Agent contract, adapters, capabilities, safety rules, and task-pack identifiers. | `codex`<br>`claude-code`<br>`gemini-cli`<br>`kimi-cli`<br>`ten task packs` | `machine/agents/*.json`<br>`adapter-owned guidance files` | — | Unknown fields, prompt boundary violations, or conflicts fail validation. |
| `vibesec.artifacts.security` | `stable` | profile orchestration | Sanitized scan artifacts and their publication boundary. | `required artifact set varies only by documented profile` | `normalized.json`<br>`coverage.json`<br>`policy-result.json`<br>`report.md`<br>`optional SBOM and intelligence files` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Final artifacts preserve the originating non-clean category and stale output is removed. |
| `vibesec.capabilities.registry` | `stable` | capability model | The versioned project questionnaire and security-capability evidence registry. | `explicit Yes or No answers`<br>`46 capability IDs` | `.vibesec/project-capabilities.json`<br>`config/security-capabilities.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Unknown fields, missing answers, or inconsistent evidence fail validation. |
| `vibesec.cli.agents` | `stable` | agent guidance manager | Manage deterministic, non-executing guidance for supported coding agents. | `list`<br>`doctor`<br>`describe`<br>`plan`<br>`verify`<br>`upgrade-plan`<br>`install`<br>`disable`<br>`enable`<br>`remove`<br>`render-task`<br>`--target`<br>`--write`<br>`--json` | `.vibesec/agents/installed.json`<br>`adapter-owned guidance files` | — | 0 success; 1 review warning; 2 verification failure; 3 invalid input; 4 infrastructure failure. |
| `vibesec.cli.doctor` | `stable` | installation doctor | Diagnose an installed VibeSec profile without changing it. | `--target`<br>`--profile minimal&#124;standard`<br>`--json` | — | — | 0 healthy; 1 actionable warnings; 2 verification failure; 3 invalid input; 4 infrastructure failure. |
| `vibesec.cli.extensions` | `stable` | extension manager | List, verify, describe, install, disable, enable, remove, plan, and run verified local extensions. | `list`<br>`verify`<br>`describe`<br>`install`<br>`disable`<br>`enable`<br>`remove`<br>`upgrade-plan`<br>`run`<br>`--target`<br>`--repository`<br>`--results`<br>`--profile minimal&#124;standard`<br>`--write`<br>`--json` | `.vibesec/extensions/installed.json`<br>`sanitized extension artifacts` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | 0 success; 1 review warning; 2 verification or extension failure; 3 invalid input; 4 infrastructure failure. |
| `vibesec.cli.init` | `stable` | initializer | Preview or initialize a profile or add-on from source or a verified bundle. | `--profile minimal&#124;standard`<br>`--addon dast-baseline&#124;api-security-baseline&#124;api-fuzzing`<br>`--target`<br>`--stage support&#124;workflow`<br>`--bundle`<br>`--source-commit`<br>`--api-schema`<br>`--api-image-variable-name`<br>`--api-port`<br>`--api-base-path`<br>`--api-safe-methods-only true&#124;false`<br>`--fuzzing-mode contract&#124;fuzz&#124;injection&#124;combined`<br>`--fuzzing-enabled`<br>`--injection-testing-enabled`<br>`--fuzzing-safe-methods-only true&#124;false`<br>`--fuzzing-mutating-methods`<br>`--fuzzing-max-examples`<br>`--fuzzing-max-failures`<br>`--fuzzing-request-timeout`<br>`--fuzzing-total-timeout`<br>`--auth-secret-name`<br>`--capabilities-file`<br>`--all-capabilities`<br>`--write` | `.vibesec/installation-manifest.json`<br>`.vibesec/project-capabilities.json`<br>`selected workflow and support files` | — | 0 success; 2 conflict or verification failure; 3 invalid configuration; 4 infrastructure failure. |
| `vibesec.cli.scan` | `stable` | portable CLI | Run the Minimal or Standard profile against a local repository. | `--target`<br>`--results`<br>`--profile minimal&#124;standard`<br>`--execution-mode native&#124;container&#124;auto`<br>`--tool-dir`<br>`--json` | `normalized.json`<br>`coverage.json`<br>`policy-result.json`<br>`report.md` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | 0 clean; 1 policy violation; 2 scanner or runtime failure; 3 invalid input. |
| `vibesec.cli.upgrade-plan` | `stable` | upgrade planner | Produce a deterministic, non-mutating installation upgrade plan. | `--target`<br>`--bundle`<br>`--json` | — | — | 0 no conflicts; 1 review required; 2 verification failure; 3 invalid input; 4 infrastructure failure. |
| `vibesec.cli.verify` | `stable` | installation verifier | Verify installed files and provenance without changing the target. | `--target`<br>`--json` | — | — | 0 verified; 2 verification failure; 3 invalid input; 4 infrastructure failure. |
| `vibesec.compatibility.platforms` | `stable` | platform support | Honest host, runner, Docker, Windows, and GHES support claims. | `Linux x86_64`<br>`Linux arm64`<br>`macOS x86_64`<br>`macOS arm64`<br>`GitHub-hosted Ubuntu`<br>`self-hosted runner 2.327.1 or later`<br>`Windows and GHES limitations` | `config/portable-execution.json`<br>`config/github-actions.json` | — | Unsupported platform/profile combinations fail closed. |
| `vibesec.configuration.contract` | `stable` | configuration and distribution | Versioned configuration files, environment variables, bundle layout, and strict parser boundary. | `environment variable registry`<br>`adoption catalog`<br>`tool pins`<br>`profile and add-on configuration` | `config/*.json`<br>`config/*.yaml`<br>`config/*.toml`<br>`vibesec-consumer-bundle.zip` | — | Ambiguous, oversized, duplicate-key, unsafe-path, or unknown-field input fails closed. |
| `vibesec.coverage.states` | `stable` | coverage model | Exact scanner coverage state vocabulary. | `ran: scanner completed the declared scope`<br>`not_applicable: scope is provably irrelevant`<br>`not_configured: required opt-in input is absent`<br>`tool_error: scanner or runtime failed` | `coverage.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | tool_error is non-clean; not_configured is never represented as ran. |
| `vibesec.execution.modes` | `experimental` | portable execution | Native, container, and auto portable-execution selection. | `native`<br>`container`<br>`auto` | — | — | Unavailable modes fail closed with invalid input rather than silently changing execution. |
| `vibesec.extensions.contract` | `stable` | extension platform | Extension manifest, kind, permission, lifecycle, and execution contract. | `scanner kind`<br>`declared permissions`<br>`enabled or disabled state` | `vibesec-extension.json`<br>`.vibesec/extensions/installed.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Unknown manifest fields, permissions, paths, or execution outcomes fail closed. |
| `vibesec.findings.contract` | `stable` | normalization and finding intelligence | Normalized findings, correlation groups, and priority records. | `deterministic fingerprints`<br>`scanner-independent severity`<br>`bounded evidence` | `normalized.json`<br>`finding-groups.json`<br>`prioritized-findings.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Malformed scanner input is a parser failure, never a clean result. |
| `vibesec.policies.contract` | `stable` | policy gate | Observe, new, and all enforcement plus independent profile baselines and suppressions. | `observe`<br>`new`<br>`all`<br>`minimum severity` | `policy-result.json`<br>`policy/*.json`<br>`policy/*.yml` | — | 0 no violation; 1 policy violation; 3 malformed policy or input. |
| `vibesec.profiles.api-fuzzing` | `conditionally_enforced` | API fuzzing add-on | Opt-in bounded active API fuzzing and inert injection-marker testing. | `mode contract&#124;fuzz&#124;injection&#124;combined`<br>`enabled and injection_testing_enabled`<br>`safe_methods_only and mutating_methods`<br>`max_examples`<br>`max_failures`<br>`per_request_timeout_seconds`<br>`total_timeout_seconds`<br>`policy settings` | `fuzzing-findings.json`<br>`fuzzing-coverage.json`<br>`fuzzing-policy-result.json`<br>`fuzzing-report.md`<br>`finding-groups.json`<br>`prioritized-findings.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Uses the scanner exit-code contract 0 through 3. |
| `vibesec.profiles.api-security-baseline` | `conditionally_enforced` | API security add-on | Opt-in bounded OpenAPI contract testing against an isolated prebuilt API image. | `API target, schema, port, base path, safe-method, policy, and optional auth settings` | `normalized.json`<br>`coverage.json`<br>`policy-result.json`<br>`report.md`<br>`finding-groups.json`<br>`prioritized-findings.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Uses the scanner exit-code contract 0 through 3. |
| `vibesec.profiles.authenticated-security-testing` | `conditionally_enforced` | authenticated testing layer | Optional bearer-authenticated comparison for passive DAST and OpenAPI testing. | `VIBESEC_AUTH_MODE none&#124;bearer`<br>`secret name only` | `normalized.json`<br>`coverage.json`<br>`policy-result.json`<br>`report.md`<br>`finding-groups.json`<br>`prioritized-findings.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Scanner, parser, redaction, publication, and cleanup failures remain non-clean. |
| `vibesec.profiles.dast-baseline` | `conditionally_enforced` | DAST add-on | Opt-in passive ZAP testing of an explicitly supplied prebuilt application image. | `VIBESEC_DAST_IMAGE_REFERENCE`<br>`VIBESEC_DAST_CONTAINER_PORT`<br>`VIBESEC_DAST_BASE_PATH`<br>`DAST policy variables` | `normalized.json`<br>`coverage.json`<br>`policy-result.json`<br>`report.md`<br>`finding-groups.json`<br>`prioritized-findings.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Uses the scanner exit-code contract 0 through 3. |
| `vibesec.profiles.minimal` | `stable` | Minimal profile | Source, secret, and workflow linting with Trivy, Gitleaks, and actionlint. | `VIBESEC_ENFORCEMENT`<br>`VIBESEC_MIN_SEVERITY`<br>`VIBESEC_TOOL_DIR` | `normalized.json`<br>`coverage.json`<br>`policy-result.json`<br>`report.md` | `ran`<br>`tool_error` | Uses the scanner exit-code contract 0 through 3. |
| `vibesec.profiles.standard` | `stable` | Standard profile | Minimal plus SAST, dependency analysis, SBOM, IaC, optional image scanning, and finding intelligence. | `Minimal variables`<br>`VIBESEC_NETWORK_MODE`<br>`OSV offline database variables`<br>`VIBESEC_IMAGE_REFERENCE` | `normalized.json`<br>`coverage.json`<br>`policy-result.json`<br>`report.md`<br>`inventory.json`<br>`sbom.cyclonedx.json`<br>`sbom.spdx.json`<br>`finding-groups.json`<br>`prioritized-findings.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Uses the scanner exit-code contract 0 through 3. |
| `vibesec.release.contract` | `stable` | release candidate pipeline | Deterministic consumer bundle, SBOMs, readiness, manifest, provenance, checksums, and optional OIDC signature bundle. | `local-preparation or trusted-github-workflow creation mode` | `vibesec-consumer-bundle.zip`<br>`sbom.cyclonedx.json`<br>`sbom.spdx.json`<br>`release-readiness.json`<br>`release-manifest.json`<br>`provenance.intoto.jsonl`<br>`SHA256SUMS`<br>`SHA256SUMS.sigstore.json when signed` | — | Any missing, extra, mismatched, non-canonical, unsigned-when-required, or tampered artifact fails verification. |
| `vibesec.results.lifecycle` | `stable` | distribution lifecycle | Machine-readable doctor, verification, upgrade-plan, and operation envelopes. | `--json` | `optional caller-selected verification record` | — | Status text and numeric exit category agree; errors are not represented as success. |
| `vibesec.runtime.exit-codes` | `stable` | shared command runtime | Process exit categories for scanning, distribution, lifecycle, and verification commands. | `scanner: 0 clean, 1 policy violation, 2 tool failure, 3 invalid input`<br>`lifecycle: 0 success, 1 warnings, 2 verification failure, 3 invalid input, 4 infrastructure failure` | — | — | A non-clean category is never converted to clean success; parser and infrastructure failures remain distinct. |
| `vibesec.scanners.registry` | `stable` | tool inventory | Pinned scanner and supporting security-tool identities. | `trivy`<br>`gitleaks`<br>`actionlint`<br>`opengrep`<br>`osv-scanner`<br>`syft`<br>`cosign`<br>`checkov`<br>`zap-baseline`<br>`dast-fixture-python`<br>`schemathesis` | `config/tools.json` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Unavailable or failing scanners remain tool_error and non-clean. |
| `vibesec.workflows.contract` | `stable` | GitHub Actions integration | Copyable profile templates, trusted integration workflows, and aggregate CI status. | `five adoption templates`<br>`five live integration workflows`<br>`ci.yml`<br>`release-candidate.yml`<br>`required status validate` | `GitHub Actions artifacts documented per workflow` | `ran`<br>`not_applicable`<br>`not_configured`<br>`tool_error` | Every required offline job must succeed before validate succeeds. |

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
| `fuzzing-coverage.json` | `stable` |
| `fuzzing-findings.json` | `stable` |
| `fuzzing-policy-result.json` | `stable` |
| `fuzzing-report.md` | `stable` |
| `inventory.json` | `stable` |
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
