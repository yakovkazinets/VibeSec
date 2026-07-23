# API fuzzing threat model

## Assets and trust boundaries

Primary assets are the target's data and availability, bearer credentials when explicitly enabled, the trusted harness, the reviewed OpenAPI document, policy, and sanitized artifacts. The target image and its responses are untrusted data. Project-provided hooks, payload files, scanner configuration, commands, public URLs, and raw artifacts are not trusted inputs.

The trusted host validates capabilities, local schema structure, installed configuration, payload registry, image digests, operation count, method selection, and every hard ceiling before Docker. The target and scanner then run on a new `--internal` network. No host port, host network, Docker socket, privilege, capability, writable root, project dependency installation, arbitrary command, external egress, or schema-selected origin is permitted.

## Abuse cases and controls

- Unintended activation is prevented by `api_fuzzing_target`, separate enable flags, manual/scheduled workflows, and safe-method defaults.
- Denial-of-service risk is bounded by one worker, 25 examples and failures per operation, five-second requests, a 15-minute total timeout, 200 operations, fixed request/response limits, container resource limits, and deterministic cleanup.
- Destructive or exfiltrating payloads are prevented by an exact strict registry, prohibited-content validation, no custom payload paths, and no external callbacks.
- Credential exposure is limited by scanner-step-only secret scope, stdin delivery, exact bearer use, authentication-header exclusion, redaction, bounded diagnostics, artifact validation, and raw evidence deletion.
- Target escape and external access are limited by immutable images, non-root target enforcement, an internal Docker network, no host publication, dropped capabilities, `no-new-privileges`, and no Docker socket.
- False vulnerability claims are limited by reviewed evidence reasons, conservative titles, explicit limitations, and a rule that payload delivery alone is not a finding.
- Parser or tool ambiguity fails closed as exit 2 or 3 and `tool_error`; it cannot be represented as clean.
- Artifact disclosure is limited to sanitized operation, route, family, reason, status, confidence, fingerprint, authentication context, and replay seed. Raw bodies and exact schema-derived values are never published.

## Residual risk

Even bounded active requests can alter a poorly designed application, trigger target-specific side effects, or miss stateful and semantic behavior. Safe HTTP methods do not guarantee application-level read-only behavior. An immutable container digest does not prove the target is defect-free. Scanner and schema limitations can create false positives and false negatives. Abrupt runner termination can leave current-run Docker resources until runner cleanup. Use only disposable isolated targets backed by non-production data.

Passing this profile does not prove injection safety and is not a substitute for threat modeling, secure design review, code review, penetration testing, or qualified security review.
