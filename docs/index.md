# VibeSec documentation

This is the curated documentation index for VibeSec v1 preparation. Exact public IDs and statuses come from [`machine/`](../machine/); the generated [v1 interface reference](v1-interface-reference.md) is checked for drift.

## Adopt and operate

- [Project overview and limitations](../README.md)
- [Five-minute quick start](quickstart.md)
- [Installation and distribution](distribution.md)
- [Project capability questionnaire](project-capabilities.md)
- [Profile selection](profile-selection.md)
- [Minimal and Standard configuration](configuration.md)
- [Local execution](local-execution.md)
- [Platform support](platform-support.md)
- [Doctor](doctor.md), [installation verification](installation-verification.md), and [upgrades](upgrading.md)
- [Troubleshooting](troubleshooting.md)

## Security capabilities

- [Security model](security-model.md) and [top-level threat model](threat-model.md)
- [Minimal and Standard capability matrix](security-capability-matrix.md)
- [Framework SAST coverage](framework-sast-coverage.md)
- [Finding intelligence](finding-intelligence.md)
- [Policies, baselines, and suppressions](security-validation-policy.md)
- [Passive DAST](dast-baseline.md) and its [threat model](dast-threat-model.md)
- [OpenAPI API security](api-security-baseline.md) and its [threat model](api-security-threat-model.md)
- [Authenticated testing](authenticated-security-testing.md) and its [threat model](authenticated-security-threat-model.md)
- [API fuzzing](api-fuzzing.md), [injection testing](injection-testing.md), and the [fuzzing threat model](fuzzing-threat-model.md)

## Extend and automate

- [GitHub Actions runtime](github-actions-runtime.md)
- [Extensions](extensions.md), [authoring](extension-authoring.md), and [security model](extension-security-model.md)
- [Multi-agent support](multi-agent-support.md), [adapters](agent-adapters.md), [task packs](agent-task-pack.md), [installation](agent-installation.md), [upgrades](agent-upgrades.md), and [safety](agent-safety-model.md)
- [Imported skill validation](skill-validation.md)

## Distribution and release assurance

- [Consumer bundle verification](distribution.md)
- [Software supply-chain assurance](software-supply-chain-assurance.md)
- [Release signing](release-signing.md), [provenance](provenance.md), and [release threat model](release-threat-model.md)
- [v1 stability and deprecation policy](v1-stability-policy.md)
- [v1 support policy](v1-support-policy.md)
- [v1 migrations](v1-migrations.md)
- [v1 security review](v1-security-review.md)
- [v1 release readiness](v1-release-readiness.md)
- [Tested examples](examples.md)
- [Generated v1 interface reference](v1-interface-reference.md)

## Maintainers and security reviewers

- [Architecture](architecture.md)
- [Tool selection](tool-selection.md)
- [Self-hosted validation](self-hosted-validation.md)
- [Security reporting](../SECURITY.md)
- [Contribution requirements](../CONTRIBUTING.md)
- [Release history and Unreleased changes](../CHANGELOG.md)
