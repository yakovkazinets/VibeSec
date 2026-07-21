# Example: overlapping scanners

## Evidence

A TypeScript repository already runs Dependabot, Trivy filesystem scanning, and a custom Semgrep ruleset. It has no dedicated secret scanner or workflow linter.

## Response pattern

Preserve the existing controls. Do not add another general dependency scanner merely because a profile lists one, and do not replace or weaken the custom Semgrep rules. Review their versions, triggers, permissions, failure behavior, and artifact handling.

For Minimal, propose only the uncovered controls: Gitleaks for dedicated secret detection and actionlint for GitHub Actions. Explain that Trivy secret scanning may overlap with Gitleaks, but the dedicated engine adds independent patterns; plan fingerprint-based deduplication.

For Standard, do not add VibeSec Opengrep over the existing Semgrep rules without a documented gap and maintainer agreement. Consider OSV-Scanner only if it adds an independently useful advisory source beyond Dependabot and existing Trivy coverage; if selected, make it the primary source-dependency scanner and turn off only the overlapping Trivy vulnerability mode while preserving Trivy secrets/configuration. Generate Syft SBOMs if absent. Run Checkov only if IaC is detected. Record every omitted component as `not_applicable` or `not_configured`, never clean.

Flag the Semgrep engine and rule licenses for maintainer verification without inventing their terms. Explain OSV online metadata transmission before enabling it for a private repository.

Keep scanner findings separate by confidence and report execution failures independently. Any suppression must retain a reason, owner, and expiration. End with explicit gaps such as runtime behavior and DAST not checked.
