# DAST Baseline threat model

Static bearer authentication adds a separate credential boundary. Its secret lifecycle, scanner-delivery path, redaction rules, and authenticated-versus-unauthenticated correlation model are defined in [Authenticated security testing threat model](authenticated-security-threat-model.md).

## Assets and trust boundaries

Protected assets include runner credentials, the Docker daemon, neighboring networks, external services, scanner integrity, target image identity, and sanitized evidence. Trusted inputs are the checked-in VibeSec harness, immutable tool pins, repository variables configured by maintainers, and trusted-event metadata. Application image contents and HTTP responses are hostile scan data. Pull-request text, mutable tags, external URLs, application-supplied scanner configuration, and authentication material are never trusted configuration.

The registry pull is the only intended external network activity. After pull and image metadata validation, target and scanner run on a unique Docker internal network without published ports. The target receives no host mount, environment secret, custom entrypoint, or command. ZAP receives one restrictive private workspace containing only the generated trusted plan and its raw report; no repository source or target-controlled configuration is mounted. Container resource bounds limit but cannot eliminate denial-of-service risk.

## Fail-closed rules

- Only scheduled or manually dispatched trusted events can start the target.
- Both target and scanner references are digest-pinned; the target must declare a non-root user.
- The Automation Framework command is fixed to `zap.sh -cmd -silent -dir /zap/vibesec-home -autorun /zap/wrk/vibesec-zap-plan.yaml`; the explicit home is a bounded per-container tmpfs, the plan contains no add-ons job, and callers cannot extend either command or plan.
- The exact plan permits only one internal context followed by traditional spider, passive wait, traditional JSON report, and trusted exit-status jobs. Active, AJAX/client, import, API, authentication, requestor, replacer, and script jobs fail validation.
- The origin is exactly `http://target:<configured-port>` and normalized findings may contain only safe paths from that origin.
- Raw JSON is size-, shape-, field-, count-, URL-, and control-character validated before policy processing.
- Parser/configuration failure is exit `3`; runtime or cleanup failure is exit `2`; neither is a clean scan.
- Cleanup removes the scanner, target, internal network, generated plan, and private raw report. A cleanup failure changes the result to a tool failure.
- Live accountability failure diagnostics inspect only the stopped current-run scanner. Bounded raw log data is parsed privately, never uploaded or printed, and its temporary copy is deleted before container and network cleanup.
- Artifact validation rejects prohibited raw or sensitive fields and only the four sanitized artifacts are uploaded.

## Residual risk and exclusions

Running any untrusted application image exercises application code and shares a Docker kernel boundary with the runner. Non-root execution, read-only filesystems, capability removal, no-new-privileges, resource bounds, no host mounts, and internal networking reduce but do not remove container-escape or resource-exhaustion risk. Use a disposable trusted runner and review the image provenance.

The add-on deliberately excludes active attacks, AJAX spidering, authentication, credentials, browser automation, external targets, target builds, dependency installation, lifecycle scripts, user-supplied commands, and arbitrary ZAP options. Passive results are coverage evidence, not a security guarantee.
