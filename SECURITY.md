# Security Policy

Reports about the optional DAST Baseline should identify whether the issue affects target isolation, immutable image validation, non-root enforcement, event gating, external egress, passive-only behavior, raw-report handling, normalization, policy separation, cleanup, or artifact sanitization. Do not include live credentials, private application responses, raw ZAP reports, or exploitable production targets in an issue.

Release-assurance reports should identify whether the issue affects deterministic bundles, checksum or manifest validation, SBOM or provenance linkage, GitHub OIDC identity, Sigstore verification, immutable tool/action pins, workflow permissions, or untrusted trigger isolation. Do not attach private keys, OIDC tokens, raw certificates containing unexpected personal identity, or unreleased private artifacts. Signing establishes provenance and integrity, not that software is safe.

## Reporting a vulnerability

Do not open a public issue for a vulnerability in VibeSec. Use GitHub private vulnerability reporting when it is enabled for the repository. If that channel is unavailable, contact a maintainer through a private channel listed in their GitHub profile and request a disclosure channel without including exploit details in the first message.

Include the affected version or commit, impact, reproduction conditions, and a minimal safe demonstration. Never include real credentials, personal data, or third-party source code.

Maintainers will acknowledge a complete report when practical, assess scope, coordinate a fix, and credit reporters who request attribution. No response-time or bounty guarantee is offered.

## Scope and safe handling

The policy covers VibeSec scripts, workflows, templates, policy logic, and documentation. Scanner vulnerabilities should also be reported to their upstream projects. Do not test against systems you do not own or lack permission to assess.

Official release preparation must originate from protected `main`, use the manual reviewed workflow, and pass the required `validate` aggregate. Maintainers must compare the intended version and commit before approving a candidate; no source-tree branch can by itself prove repository settings or signing identity are uncompromised.
