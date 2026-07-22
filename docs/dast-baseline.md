# Passive DAST Baseline add-on

The DAST Baseline is a separate, opt-in add-on for an existing VibeSec Minimal or Standard installation. It accepts one explicitly configured immutable application image, starts it as its declared non-root user, and runs the pinned OWASP ZAP baseline scanner. The add-on does not build a Dockerfile, install dependencies, run setup commands, accept authentication material, publish a host port, or scan an external URL.

Only `workflow_dispatch` and `schedule` are trusted. Pull-request events produce `not_configured` without starting the target; unknown events fail closed. The copyable workflow intentionally exposes only `workflow_dispatch`. Configure repository variables `VIBESEC_DAST_IMAGE_REFERENCE`, and optionally `VIBESEC_DAST_CONTAINER_PORT` and `VIBESEC_DAST_BASE_PATH`. The image must use `registry/name@sha256:<64 lowercase hex>` and declare a non-root user in image metadata.

## Isolation and scan mode

The runner creates a unique Docker `--internal` network. The target and ZAP containers share only that network, with the target reachable as `http://target:<port><path>`. Both containers are read-only, drop all capabilities, use `no-new-privileges`, and have CPU, memory, PID, timeout, and tmpfs bounds. No source tree, credentials, Docker socket, or arbitrary command is mounted into the target. ZAP uses the traditional spider and passive scanner only; AJAX spidering, active scanning, authentication, and external egress are disabled.

The reviewed ZAP policy allows only passive rule `10020` (missing anti-clickjacking header) to produce a normalized finding. ZAP exit `0`, `1`, or `2` means its baseline run completed and the raw JSON must still pass structural validation. Exit `3`, Docker/runtime failure, malformed or off-origin output, cleanup failure, and invalid trusted configuration remain distinct failures.

## Results and policy

Only `normalized.json`, `coverage.json`, `policy-result.json`, and `report.md` are retained. Raw ZAP output is private temporary data and is deleted. Normalization retains a bounded rule ID, severity, confidence, sanitized path, HTTP method, optional CWE/WASC IDs, remediation, and stable fingerprint. It omits query strings, response bodies, evidence, cookies, headers, absolute host paths, and arbitrary scanner metadata.

DAST uses independent `policy/dast-baseline.json` and `policy/dast-suppressions.json` files. Suppression entries follow the common policy schema and must be reviewed, scoped, justified, owned, and time-bounded. Minimal and Standard baselines cannot suppress DAST findings. Exit codes are `0` completed without policy violation, `1` policy violation, `2` tool/runtime failure, and `3` invalid configuration or malformed scanner evidence.

## Install and operate

Install Minimal or Standard first, then run:

```sh
python3 scripts/init_vibesec.py --addon dast-baseline --target /path/to/repository --write
python3 scripts/verify_installation.py --target /path/to/repository --json
```

Review the copied workflow and configuration before enabling it. A successful passive, unauthenticated crawl does not establish that an application is secure. It does not assess authorization, business logic, authenticated surfaces, injection resistance, APIs unreachable through links, or stateful workflows.
