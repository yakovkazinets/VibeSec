# Security Policy

Reports about the optional DAST Baseline should identify whether the issue affects target isolation, immutable image validation, non-root enforcement, event gating, external egress, passive-only behavior, raw-report handling, normalization, policy separation, cleanup, or artifact sanitization. Do not include live credentials, private application responses, raw ZAP reports, or exploitable production targets in an issue.

## Reporting a vulnerability

Do not open a public issue for a vulnerability in VibeSec. Use GitHub private vulnerability reporting when it is enabled for the repository. If that channel is unavailable, contact a maintainer through a private channel listed in their GitHub profile and request a disclosure channel without including exploit details in the first message.

Include the affected version or commit, impact, reproduction conditions, and a minimal safe demonstration. Never include real credentials, personal data, or third-party source code.

Maintainers will acknowledge a complete report when practical, assess scope, coordinate a fix, and credit reporters who request attribution. No response-time or bounty guarantee is offered.

## Scope and safe handling

The policy covers VibeSec scripts, workflows, templates, policy logic, and documentation. Scanner vulnerabilities should also be reported to their upstream projects. Do not test against systems you do not own or lack permission to assess.
