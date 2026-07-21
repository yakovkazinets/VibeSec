# Example: overlapping scanners

## Evidence

A TypeScript repository already runs Dependabot, Trivy filesystem scanning, and a custom Semgrep ruleset. It has no dedicated secret scanner or workflow linter.

## Response pattern

Preserve the existing controls. Do not add another general dependency scanner merely because a profile lists one, and do not replace or weaken the custom Semgrep rules. Review their versions, triggers, permissions, failure behavior, and artifact handling.

Propose only the uncovered minimal controls: Gitleaks for dedicated secret detection and actionlint for GitHub Actions. Explain that Trivy secret scanning may overlap with Gitleaks, but the dedicated engine adds independent patterns; plan fingerprint-based deduplication. Flag the Semgrep engine and rule licenses for maintainer verification without inventing their terms.

Keep scanner findings separate by confidence and report execution failures independently. Any suppression must retain a reason, owner, and expiration. End with explicit gaps such as runtime behavior and DAST not checked.
