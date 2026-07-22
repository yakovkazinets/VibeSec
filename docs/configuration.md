# Configuration reference

Project scope is declared separately in `.vibesec/project-capabilities.json`; see [project capabilities](project-capabilities.md). Exact Boolean answers are authoritative over detection. Validate edits with `python3 scripts/validate_project_capabilities.py`. A declared absent scope becomes `not_applicable`, while an applicable but unavailable optional input is `not_configured`; neither means clean.

`config/environment-variables.json` is the machine-readable source for this page. Unsupported values and malformed configuration fail closed; they are not clean results. Environment values must come from reviewed workflow configuration, not untrusted pull-request text.

GitHub Action pins and embedded runtimes are configured only through the strict `config/github-actions.json` inventory. The supported baseline is Node 24 on Actions Runner 2.327.1 or newer; Node 20 runtime fallback and runtime-forcing environment overrides are invalid. These settings concern third-party actions, not an npm or Node runtime required by VibeSec. See [GitHub Actions runtime and pin policy](github-actions-runtime.md).

| Variable | Profile | Type/default | Accepted values | Security and privacy effect | Failure and example |
|---|---|---|---|---|---|
| `VIBESEC_ENFORCEMENT` | Minimal, Standard | enum / `observe` | `observe`, `new`, `all` | Selects policy gating; no privacy effect | unsupported exits 3; `new` |
| `VIBESEC_MIN_SEVERITY` | Minimal, Standard | enum / `high` | `low`, `medium`, `high`, `critical` | Sets minimum enforced severity; no privacy effect | unsupported exits 3; `high` |
| `VIBESEC_TOOL_DIR` | Minimal | path / `<target>/.tools/bin` | trusted executable directory | Changes which scanner binaries execute; never place secrets here | missing tools become tool errors; `/opt/vibesec-tools` |
| `VIBESEC_NETWORK_MODE` | Standard | enum / `online` | `online`, `offline` | Online OSV can transmit package metadata/file hashes; offline uses local data | incomplete offline config exits 3; `offline` |
| `VIBESEC_OSV_DATABASE_DIR` | Standard offline | path / none | existing local OSV root | Supplies advisories locally; path is not uploaded and should not contain credentials | missing/malformed database exits 3; `/srv/osv-db` |
| `VIBESEC_OSV_DATABASE_DATE` | Standard offline | date / none | `YYYY-MM-DD` | Declares freshness; not sensitive | missing/future/stale exits 3; `2026-07-21` |
| `VIBESEC_OSV_MAX_DATABASE_AGE_DAYS` | Standard offline | integer / `7` | non-negative integer | Limits stale advisory use; not sensitive | invalid/exceeded age exits 3; `7` |
| `VIBESEC_IMAGE_REFERENCE` | Standard | string / empty | immutable `registry/name@sha256:<digest>` | Trusted-event scan may contact registry; do not include credentials | malformed/tag-only exits 3; pull requests disable it |
| `VIBESEC_DAST_IMAGE_REFERENCE` | DAST Baseline | string / empty | immutable `registry/name@sha256:<digest>` | Starts a prebuilt non-root target on an internal Docker network; registry access occurs only while pulling | missing means `not_configured`; malformed, mutable, or root image exits 3 |
| `VIBESEC_DAST_CONTAINER_PORT` | DAST Baseline | integer / `8080` | `1`–`65535` | Selects only the target's internal HTTP port; no host port is published | invalid exits 3; `8080` |
| `VIBESEC_DAST_BASE_PATH` | DAST Baseline | path / `/` | bounded absolute path without query, fragment, credentials, or traversal | Bounds the passive crawl start; sanitized paths can appear in reports | invalid exits 3; `/health` |
| `VIBESEC_DAST_ENFORCEMENT` | DAST Baseline | enum / `observe` | `observe`, `new`, `all` | Selects the independent DAST policy gate | unsupported exits 3; `new` |
| `VIBESEC_DAST_MIN_SEVERITY` | DAST Baseline | enum / `high` | `low`, `medium`, `high`, `critical` | Sets the minimum DAST severity eligible for enforcement | unsupported exits 3; `medium` |

`VIBESEC_ROOT`, `VIBESEC_RESULTS`, and `VIBESEC_TOOLS` are Standard starter internals created under the runner temporary directory. `VIBESEC_DAST_RESULTS` is the DAST starter's runner-temporary sanitized report directory. Consumers should not populate these internals from pull-request inputs.

Result destinations are positional command arguments, not environment configuration. Minimal defaults to `results`; Standard's starter uses `$RUNNER_TEMP/vibesec-results`. No supported `VIBESEC_*` variable may contain a secret. Registry credentials are intentionally not accepted by the starter.

OSV offline mode requires `<ecosystem>/all.zip` archives under the database root and a declared date within the configured maximum age. VibeSec validates them but never downloads or refreshes them. `VIBESEC_IMAGE_REFERENCE` is ignored as coverage on `pull_request` and unknown GitHub events even when supplied; the coverage report records `not_configured`.
