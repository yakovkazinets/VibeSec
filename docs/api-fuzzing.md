# Bounded API fuzzing

VibeSec Guardian's `api-fuzzing` add-on extends the opt-in OpenAPI API Security Baseline with bounded, stateless active testing. It is supported only when `api=true`, `container_image=true`, `api_security_target=true`, and `api_fuzzing_target=true`. The VibeSec Guardian repository declares `api_fuzzing_target=false`, so its state is exactly `not_applicable` and it is never fuzzed.

The installed `.vibesec/api-fuzzing.json` supports four explicit modes: `contract`, `fuzz`, `injection`, and `combined`. Installation defaults to `contract`, with `fuzzing_enabled=false`, `injection_testing_enabled=false`, and `safe_methods_only=true`. Selecting `fuzz` or `combined` requires `--fuzzing-enabled`; selecting `injection` or `combined` requires `--injection-testing-enabled`. POST, PUT, PATCH, and DELETE additionally require both `--fuzzing-safe-methods-only false` and `--fuzzing-mutating-methods`. Existing installations do not become stricter or more active automatically.

Reviewed ceilings are one worker, 25 generated examples per operation, 25 failures, five seconds per request, 15 minutes total, 200 operations, 64 KiB request bodies, 256 KiB response reads, 1,000 normalized findings, and 64 KiB diagnostics. Consumer values may be lowered but never raised. Stateful testing, project hooks/configuration, custom payload paths, authentication-header mutation, raw-body artifacts, public targets, remote schemas, external callbacks, file uploads, GraphQL, WebSockets, browser testing, race testing, brute force, and unrestricted concurrency or payloads fail closed.

The public installer flags for the adjustable ceilings are:

| Flag | Default | Accepted range |
|---|---:|---:|
| `--fuzzing-max-examples` | 25 | 1–25 |
| `--fuzzing-max-failures` | 25 | 1–25 |
| `--fuzzing-request-timeout` | 5 seconds | 1–5 |
| `--fuzzing-total-timeout` | 15 minutes | 1–15 |

These flags only lower the reviewed ceilings; values outside the range fail with invalid configuration.

Schemathesis 4.24.2 remains pinned by immutable digest. Contract and fuzz modes use only reviewed phases, checks, deterministic generation, a fixed seed, no example database, no retries, no redirects, and no stateful phase. Injection mode uses a trusted in-container launcher and the repository-owned `safe-v1` payload registry. No `pip install`, `uvx`, floating image tag, project hook, or project-provided scanner configuration is used.

The target is an immutable non-root image on a fresh internal Docker network with no host ports, host network, Docker socket, privilege, added capability, or external egress. Both target and scanner have read-only roots, dropped capabilities, `no-new-privileges`, and bounded CPU, memory, PIDs, tmpfs, time, input, output, and findings. The workflow is manual/scheduled only. The live controlled fixture remains outside required `validate`; normal CI validates the registry, commands, normalization, policy, correlation, failures, fixtures, and trust boundaries without Docker.

Published files are `fuzzing-coverage.json`, `fuzzing-findings.json`, `fuzzing-policy-result.json`, `fuzzing-report.md`, `finding-groups.json`, and `prioritized-findings.json`. Raw scanner events, exact generated schema values, raw requests, raw responses, and credentials are deleted before publication. Replay metadata contains only a bounded seed and sanitized operation identity.

Policy has its own `api-fuzzing` baseline and suppressions and supports `observe`, `new`, and `all`. Exit 0 is completed without a policy violation, 1 is a policy violation, 2 is a scanner/runtime/cleanup failure, and 3 is invalid configuration or malformed evidence. `not_applicable`, `not_configured`, and `tool_error` are never clean.

Install the API Security Baseline first, then preview active testing:

```bash
python3 scripts/init_vibesec.py --addon api-fuzzing --target /path/to/project
```

Explicitly enable combined safe-method testing only after review:

```bash
python3 scripts/init_vibesec.py --addon api-fuzzing --target /path/to/project \
  --fuzzing-mode combined --fuzzing-enabled --injection-testing-enabled --write
```

Passing does not prove injection safety, authorization correctness, or that the API is secure.
