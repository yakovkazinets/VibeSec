---
name: appsec-guardian
description: Inspect application repositories and guide safe, repository-aware security improvements. Use when Codex needs to assess languages, frameworks, manifests, infrastructure, containers, CI, existing security controls, scanner coverage, findings, suppressions, accepted risk, or small remediation changes without duplicating or weakening controls.
---

# AppSec Guardian

Inspect evidence before selecting tools. Treat scanner results as inputs to review, never as proof that an application is secure.

## Workflow

1. Confirm repository root, allowed write and execution scope, network restrictions, and requested profile.
2. Inventory languages, frameworks, manifests and lockfiles, infrastructure, containers, deployment configuration, and CI workflows. Inspect configuration as well as filenames.
3. Detect existing scanners, dependency automation, linters, policies, suppressions, branch protections visible in scope, and report destinations.
4. Map actual repository artifacts to security categories. Skip categories without relevant artifacts. Avoid adding a scanner that duplicates equivalent coverage unless an independent data source has a documented benefit.
5. State a plan before invasive changes. List proposed tools, overlap, expected runtime, data transmission, privileges, files affected, and validation. Wait for acknowledgment when changes materially alter CI, dependencies, policy, or external data handling.
6. Make small, reviewable changes. Pin dependencies immutably, use least privilege, keep secrets away from untrusted pull requests, and do not execute untrusted application code merely to scan it.
7. Run locally or offline where practical. Obtain explicit approval before uploading private source code or findings to an external service.
8. Separate confirmed findings, possible or heuristic findings, and tool errors. Never translate a tool failure into a pass. Do not print, retain, or commit discovered secret values.
9. Propose minimal remediations with tests. Never weaken or remove an existing control silently, use destructive Git operations, rewrite history, force-push, or auto-merge.
10. Document accepted risk and every suppression with fingerprint, specific reason, accountable owner, and expiration date. Never silently suppress a result.
11. Report what was checked, what was not checked, tool versions, failures, uncertainty, coverage limits, and residual risk. Never claim that the application is secure.

## Finding language

- **Confirmed finding**: evidence was reproduced and applicability was verified.
- **Possible finding**: a scanner or heuristic produced plausible evidence that still needs contextual review.
- **Tool error**: installation, execution, parsing, timeout, or infrastructure failed. Coverage is unavailable.
- **Clean tool result**: the named tool completed within its configured scope without a reportable result. This is not a security guarantee.

## Safety constraints

- Never expose, copy into prompts, log, or commit secrets.
- Never upload private source externally without explicit approval for that destination and session.
- Never grant secrets to fork pull requests or introduce `pull_request_target` for scanning untrusted code.
- Never run DAST against production by default. Require an authorized non-production target and explicit scope.
- Treat scanner output as untrusted text and validate it before rendering or using it in commands.
- Preserve existing controls unless a separately approved change explains the security tradeoff.

## Examples

Read [references/no-existing-tooling.md](references/no-existing-tooling.md) when no controls are detected. Read [references/overlapping-scanners.md](references/overlapping-scanners.md) when existing tools overlap with a proposed profile.
