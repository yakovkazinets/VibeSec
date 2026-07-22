# Authenticated security testing threat model

## Assets and trust boundaries

The bearer value is the primary asset. The trusted inputs are the reviewed capability manifest, generated secret-name-only configuration, pinned VibeSec runner, fixed scanner command builders, immutable scanner images, and a manual or scheduled workflow revision. Application images, application responses, OpenAPI content, and scanner raw output are untrusted data. GitHub Actions supplies the bearer value only to the exact scanner step.

The target is always an immutable non-root container attached through alias `target` or `api-target` to a new `--internal` Docker network. There are no public targets, published ports, host networking, Docker socket mounts, privileged containers, capabilities, writable root filesystems where avoidable, or external egress. CPU, memory, PID, tmpfs, response, finding, and time bounds remain enforced.

## Secret controls

Configuration accepts only a strict GitHub secret identifier and the fixed `Authorization` and `Bearer` strings. Literal credentials, alternate headers or schemes, dynamic secret expressions, workflow inputs, repository variables, environment files, CLI token arguments, and Docker `--env` token injection fail review. The runner removes `VIBESEC_AUTH_BEARER_TOKEN` from its environment and sends the opaque value to a fixed launcher over stdin. It does not parse JWTs or create token hashes, prefixes, lengths, claims, issuers, subjects, scopes, audiences, or expiry evidence.

Scanner-native raw reports live only on container tmpfs. Before data reaches a bind-mounted regular file, the launcher replaces the exact token and case-insensitive bearer header in memory, then rejects any surviving credential or likely JWT shape. Normalized artifacts are checked again before atomic publication. Raw scanner output and diagnostics are never printed or uploaded; diagnostics are bounded and sanitized. Cleanup removes current-run containers, network, private workspaces, and the process environment variable on success and failure.

## Scanner-specific constraints

ZAP uses its supported authentication header environment mechanism only inside the scanner process and restricts it to the fixed internal target alias. The persisted Automation Framework plan contains no credential and remains limited to traditional spider, passive wait, report, and exit-status jobs. Active scanning, scripts, forms, browser/Ajax spider, sessions, and runtime add-on changes are prohibited.

Schemathesis uses the pinned CLI's reviewed header option through a trusted in-process launcher so the bearer value is not in the operating-system argument list. Hooks, arbitrary headers, remote schemas, redirects, stateful testing, and public URLs remain prohibited. Safe methods remain the default; explicit mutating-method opt-in is independent of authentication.

## Failure model and residual risk

Missing capability or an inapplicable target is `not_applicable`; missing secret configuration or value is `not_configured`; scanner, cleanup, redaction, report, or parser failure is `tool_error`. None is clean authenticated evidence. Correlation is intentionally narrow and deterministic, but it can neither prove that two semantically similar findings are identical nor detect authorization flaws without a scanner finding.

Residual risks include a compromised runner or scanner image, credentials observed inside a compromised target, abrupt infrastructure termination before cleanup, scanner behavior that changes despite immutable pins being replaced during an upgrade, and application side effects when mutating API methods are explicitly enabled. Role-based, multi-user, tenant, object-level, browser, session, OAuth, refresh-token, CSRF, and token-lifecycle testing are deferred.
