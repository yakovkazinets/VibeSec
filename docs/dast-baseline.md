# Passive DAST Baseline add-on

When bearer-authenticated comparison is explicitly enabled, the runner additionally publishes sanitized `finding-groups.json` and `prioritized-findings.json`; unauthenticated DAST behavior and its four mandatory artifacts are unchanged.

The DAST Baseline is a separate, opt-in, `conditionally_enforced` add-on for an existing VibeSec Minimal or Standard installation. Installation requires authoritative `web_application=true` and `dast_target=true` capability answers. `dast_target=false` leaves the add-on uninstalled and reports `not_applicable`; it is not a clean result. The add-on accepts one explicitly configured immutable application image, starts it as its declared non-root user, and runs the pinned OWASP ZAP Automation Framework in a passive-only mode. It does not build a Dockerfile, install dependencies, run setup commands, publish a host port, or scan an external URL. Optional authentication supports only the separately configured static bearer model described in [authenticated security testing](authenticated-security-testing.md). VibeSec itself declares both runtime capabilities false.

Authenticated mode uses ZAP's supported header environment mechanism inside the scanner process, scoped to the fixed `target` alias. The generated Automation Framework plan contains no credential and remains traditional-spider/passive-only. Scanner-native raw JSON stays on container tmpfs until exact-token and bearer-header redaction succeeds; only the sanitized report reaches normalization. Authenticated and unauthenticated findings correlate only on the narrow same-scanner identity.

Only `workflow_dispatch` and `schedule` are trusted. Pull-request events produce `not_configured` without starting the target; unknown events fail closed. The copyable workflow intentionally exposes only `workflow_dispatch`. Configure repository variables `VIBESEC_DAST_IMAGE_REFERENCE`, and optionally `VIBESEC_DAST_CONTAINER_PORT` and `VIBESEC_DAST_BASE_PATH`. The image must use `registry/name@sha256:<64 lowercase hex>` and declare a non-root user in image metadata.

## Isolation and scan mode

The runner creates a unique Docker `--internal` network. The target and ZAP containers share only that network, with the target reachable as `http://target:<port><path>`. Both containers are read-only, drop all capabilities, use `no-new-privileges`, and have CPU, memory, PID, timeout, and tmpfs bounds. ZAP receives an explicit `/zap/vibesec-home` backed by a separate 256 MiB tmpfs owned by its injected numeric UID/GID with mode `0700`; its independently configured size is validated from 128 through 1024 MiB, and it is never host-mounted or persisted. No source tree, credentials, Docker socket, or arbitrary command is mounted into the target. ZAP uses the traditional spider and passive scanner only; AJAX/client spidering, active scanning, authentication, and external egress are disabled.

VibeSec generates a restrictive canonical JSON document that is also valid YAML and validates it against one exact plan shape before mounting it. The only jobs, in order, are `spider`, `passiveScan-wait`, `report`, and `exitStatus`; the environment contains one same-origin context. The command is exactly `zap.sh -cmd -silent -dir /zap/vibesec-home -autorun /zap/wrk/vibesec-zap-plan.yaml`. The target repository and workflow inputs cannot provide the home, plans, fragments, jobs, scripts, options, proxies, authentication, headers, or URLs.

The reviewed normalization policy allows only passive rule `10020` (missing anti-clickjacking header) to produce a normalized finding. The report template is exactly `traditional-json`, never the body-bearing plus template. Silent command mode and the absence of an add-ons job prevent runtime marketplace updates or installations. Exit `0` or `2`, and exit `1` with a structurally valid report produced by the reviewed `exitStatus` thresholds, represent completed automation; VibeSec applies its own policy independently. Automation failure without a report, undocumented exits, Docker/runtime failure, malformed or off-origin output, cleanup failure, and invalid trusted configuration remain non-clean failures.

## Results and policy

Only `normalized.json`, `coverage.json`, `policy-result.json`, and `report.md` are retained. The generated plan and raw ZAP output exist only in a private two-file workspace and are deleted before artifacts are published. Normalization retains a bounded rule ID, severity, confidence, sanitized path, HTTP method, optional CWE/WASC IDs, remediation, and stable fingerprint. It omits query strings, request and response bodies, evidence, cookies, headers, absolute host paths, and arbitrary scanner metadata.

DAST uses independent `policy/dast-baseline.json` and `policy/dast-suppressions.json` files. Suppression entries follow the common policy schema and must be reviewed, scoped, justified, owned, and time-bounded. Minimal and Standard baselines cannot suppress DAST findings. Exit codes are `0` completed without policy violation, `1` policy violation, `2` tool/runtime failure, and `3` invalid configuration or malformed scanner evidence.

## Install and operate

Install Minimal or Standard first. If the project later gains an eligible target, update and validate `.vibesec/project-capabilities.json`, setting both `web_application` and `dast_target` true, then run:

```sh
python3 scripts/init_vibesec.py --addon dast-baseline --target /path/to/repository --write
python3 scripts/verify_installation.py --target /path/to/repository --json
```

Review the copied workflow and configuration before enabling it. A successful passive, unauthenticated crawl does not establish that an application is secure. It does not assess authorization, business logic, authenticated surfaces, injection resistance, APIs unreachable through links, or stateful workflows.
