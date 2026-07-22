# API Security Baseline

The opt-in `api-security-baseline` add-on performs contract-driven testing of one local OpenAPI 3.0.x or 3.1.x document against one already-built immutable, non-root API image. It is separate from Minimal, Standard, and Passive DAST Baseline. It runs only on `workflow_dispatch` or `schedule`, never against VibeSec itself, a pull request, a public URL, or a host service. Optional authentication supports only the separately configured static bearer model.

Bearer mode uses the pinned Schemathesis CLI header option through a trusted in-process launcher after reading the opaque value from stdin. The value is not an OS argument, Docker environment setting, config file, curl reproduction, or report field. Raw NDJSON stays on container tmpfs until in-memory redaction and credential/JWT rejection complete. Safe methods, stateless execution, fixed origin, local schema, no hooks, and no arbitrary-header rules remain unchanged. See [authenticated security testing](authenticated-security-testing.md).

Schemathesis 4.24.2 runs from `ghcr.io/schemathesis/schemathesis@sha256:1f9f038554cc8b60ee28da38f508b9682c59affa31c1fc00c4a750b302100996`. The official MIT-licensed release and multi-platform image digest were verified against the Schemathesis GitHub release and GHCR metadata on 2026-07-22. The distributed runtime does not use pip, uvx, a floating tag, or `schemathesis/action`.

## Applicability and installation

`api_security_target=true` requires both `api=true` and `container_image=true`. Initialize a base profile first, then preview the add-on:

```shell
python3 scripts/init_vibesec.py --addon api-security-baseline --target /path/to/app \
  --api-schema openapi/api.yaml \
  --api-image-variable-name VIBESEC_API_IMAGE_REFERENCE \
  --api-port 8080 --api-base-path /api --api-safe-methods-only true
```

Review the dry-run plan and add `--write`. Creation is atomic and refuses conflicts. The named GitHub repository variable must contain `registry/name@sha256:<digest>`. The schema, port, base path, and method choice are stored in `.vibesec/api-security-baseline.json`; the workflow is rendered for the selected image-variable name. No credential is accepted there; bearer values come only from the separately named GitHub Actions secret.

## Request model and bounds

The fixed phases are examples, coverage, and fuzzing with mode `all`; stateful testing and OpenAPI links are disabled. Workers are 1, the fixed seed is 20260722, maximum examples are 20 per operation, maximum failures are 20, request timeout is 5 seconds, and total scanner timeout is 10 minutes. The schema is capped at 2 MiB and 200 operations; raw structured evidence is capped at 10 MiB and normalization at 1,000 findings.

Positive generation exercises contract-valid inputs. Negative generation deliberately sends contract-invalid inputs to verify rejection. This may cause side effects. `safe_methods_only=true` is therefore the default and permits only GET, HEAD, and OPTIONS. POST, PUT, PATCH, and DELETE require the explicit `--api-safe-methods-only false` installer choice. Even safe methods can be implemented unsafely; use only a disposable, authorized, non-production target.

## Schema restrictions

The schema must be a regular repository-relative JSON or YAML file with strict UTF-8. JSON duplicate keys fail; YAML duplicate keys, aliases, and unsafe tags fail. Only local in-document `$ref` values are accepted; `$dynamicRef`, `$recursiveRef`, `$id`, and `externalValue` are deliberately unsupported. Remote/file/absolute/traversing references, Swagger 2.0, GraphQL, callbacks, webhooks, links, external documentation, TRACE, missing/duplicate operation IDs, and server redirects outside the exact `http://api-target:<port><base-path>` origin fail closed. Schema-supplied servers never select the runtime origin.

## Checks, severity, and artifacts

The reviewed mapping is:

| Schemathesis check | VibeSec severity |
|---|---|
| `not_a_server_error` | high |
| `status_code_conformance` | medium |
| `content_type_conformance` | medium |
| `response_schema_conformance` | high |
| `negative_data_rejection` | medium |
| `positive_data_acceptance` | medium |

Unknown failed check IDs are parser errors. Schemathesis fatal, non-fatal, interrupted, unreviewed terminal, and after-run-failure events are scanner errors rather than clean results or findings. Only completed and configured failure-limit terminal states reach policy evaluation. Only the check ID, operation ID, method, sanitized path template, reviewed title/description/remediation, safe response status, repository-relative schema path, severity, and stable fingerprint survive. Request values and bodies, response bodies and headers, cookies, credentials, full URLs, reproduction commands, raw NDJSON, host paths, and container identities are never published. Raw evidence is deleted immediately after normalization.

The independent artifacts are `normalized.json`, `coverage.json`, `policy-result.json`, and `report.md`; baselines and suppressions live in the API-specific policy files. Enforcement supports `observe`, `new`, and `all`. Tool, timeout, cleanup, parser, and configuration failures remain blocking and never become clean results.

Passing means only that these bounded unauthenticated contract checks completed. It does not assess authorization, business logic, authenticated behavior, data persistence, concurrency, rate limits, browser behavior, or general exploitability, and it does not prove the API is secure. Authenticated API testing is deferred.

The starter uses immutable Node 24 GitHub Action pins and requires Actions Runner 2.327.1 or newer.
