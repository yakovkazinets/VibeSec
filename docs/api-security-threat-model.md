# API Security Baseline threat model

## Assets and trust boundary

The trusted assets are the installed harness, fixed Schemathesis image digest, command builder, limits, policy, and artifact validator. The OpenAPI document, generated inputs, API responses, and target image behavior are untrusted. Only manual and scheduled repository-owned workflow configuration may cross the runtime boundary; secrets, authentication, arbitrary headers, proxy settings, hooks, custom formats, external configuration, custom commands, and public targets cannot.

In the consumer runner, the target and scanner share a unique `docker network create --internal` network with fixed alias `api-target`. No host port, Docker socket, source mount in the target, credential, capability, privilege escalation, host network, or external egress is provided. Both containers use read-only roots and bounded tmpfs, CPU, memory, and PID limits. The target must declare a non-root user. The scanner receives only the validated schema read-only and a private mode-0700 results directory. The repository accountability harness has one narrower exception: it assigns a numeric non-root user and mounts only the reviewed fixture server into the pinned Python fixture image; it still uses the same trusted scanner command builder and isolated network.

## Schema threats

An attacker may attempt parser differentials, YAML aliases, duplicate keys, resource exhaustion, external reference loading, server redirection, callback/link behavior, path traversal, or extension-driven code. The validator uses strict UTF-8, safe alias-disabled YAML, duplicate detection, recursive bounds, regular-file containment, local-fragment-only `$ref` values, rejection of dynamic/recursive/identified/external references, closed unsupported constructs, exact origin validation, and operation limits before Docker runs. The harness supplies the URL and never executes schema extensions or code.

## Scanner-output threats

Schemathesis NDJSON may contain bodies, parameter values, headers, full request details, or hostile text. The normalizer reads only reviewed structural fields and fixed check IDs. Unknown IDs, malformed events, unsafe paths, missing completion, oversized reports, invalid status values, scanner error events, unreviewed terminal states, or after-run failures fail closed before policy evaluation. Their diagnostics are never copied into sanitized artifacts. Raw output remains private and is deleted on every exit; only sanitized artifacts are eligible for upload.

## Request and application risks

Generated negative inputs are intentionally invalid and can expose application defects or cause side effects. Safe-method mode limits methods but cannot guarantee an implementation is non-mutating. Mutating methods require explicit opt-in. Run only disposable non-production images with no database, dependency containers, credentials, or external connectivity. The harness does not infer cleanup and disables stateful sequences.

Residual risks include malicious resource use within container limits, unexpected application semantics, scanner defects, container-runtime vulnerabilities, registry compromise, abruptly terminated runner cleanup, and incomplete contract coverage. A successful scan is not evidence of authorization, business-logic, runtime, or comprehensive API security.
