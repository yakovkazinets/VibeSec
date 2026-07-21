# Troubleshooting

Run a read-only preflight from the consumer repository:

```shell
python3 scripts/preflight.py --profile minimal --target .
python3 scripts/preflight.py --profile standard --target .
```

Exit `0` means required files/configuration passed preflight; `2` means missing or malformed installation state; `3` means the target itself is invalid. Preflight downloads nothing and does not execute scanners, Git, package managers, application code, workflows, Dockerfiles, or IaC.

## Installation and bootstrap

- **Missing VibeSec file:** preflight identifies the path. Run the initializer dry run from the matching VibeSec version and compare the installation manifest. Do not copy one missing file from a different release.
- **Standard workflow absent:** support bootstrap is incomplete. Merge support files to the default branch, then run the documented `--stage workflow` dry run and write in a second change.
- **Filename conflict or partial install:** initializer exit `2` lists every conflict and creates nothing. Preserve existing files; compare ownership and resolve manually. There is no force option.
- **Unsupported architecture:** installers require Linux x86_64. Use the supported GitHub runner; do not substitute unverified binaries.

## Tool installation

- **Download/tool installation failure:** category `tool_error`. Confirm the runner can reach the pinned official release and has disk space. Never expose tokens in diagnostic output.
- **Checksum/signature failure:** stop. Do not change a pin to match an unexpected artifact. Verify the official upstream release, identity, checksum, and VibeSec tool manifest before a reviewed update.
- **Workflow permission failure:** starters require only `contents: read`. Check organization policy and action availability; do not add write permissions or secrets to make a pull-request scan work.

## Results and exit codes

- `0`: evaluation completed without an enforced violation. A clean configured scope is not proof of security.
- `1`: a finding violated policy.
- `2`: scanner/tool/infrastructure failure; coverage is unavailable.
- `3`: malformed configuration, policy, or scanner input; never reinterpret as clean.

`ran` means the named component completed; `not_applicable` means supported evidence was not detected; `not_configured` means optional coverage was absent or prohibited; `tool_error` means the component failed. Unsupported/empty repositories must show outside-coverage limitations even when the overall observe-mode command exits `0`.

## Scanner and parser failures

- **Malformed scanner output:** exit `3`; inspect the scanner version/pin and bounded diagnostic message. Raw output and source snippets are intentionally not uploaded.
- **Scanner execution failure:** exit `2`; identify the named component and verify its installed executable/configuration. Do not remove validation or convert errors into findings.
- **Finding detected:** inspect normalized evidence in repository context. Stay in `observe` during first adoption, then baseline only reviewed historical fingerprints and move to `new`.
- **No report:** treat as tool failure. Mandatory artifact upload intentionally errors after a scanner run that produces no report; an early CI validation failure skips upload so the original error stays visible.

## Standard-specific diagnostics

- **Dockerfile but no image reference:** `trivy-image` is `not_configured`. Supply only an already-built immutable digest on a trusted event. VibeSec never builds Dockerfiles.
- **Tag-only image reference:** invalid configuration, exit `3`. Use `registry/name@sha256:<64 lowercase hex>`.
- **Fork pull request:** image and private-registry scanning remain disabled, no secrets are passed, and coverage reports `not_configured`; this is expected trust-boundary behavior.
- **Docker unavailable:** Checkov becomes a tool error only when supported IaC requires it. Install Docker on the trusted runner or accept/document the missing IaC capability; network/capability isolation must not be weakened.
- **OSV offline database unavailable/stale:** provide `VIBESEC_OSV_DATABASE_DIR`, `VIBESEC_OSV_DATABASE_DATE`, and a suitable maximum age. VibeSec never downloads or refreshes offline data. Future, stale, empty, corrupt, linked, or oversized database content fails closed.
- **SBOM failure:** both CycloneDX and SPDX files must be valid and nonempty. A partial pair fails. SBOMs are separate because package names/versions may be sensitive.

## Artifact upload

Required normalized/report artifacts use `if-no-files-found: error`. Optional Standard SBOMs upload only as a complete validated pair. Raw scanner results are not uploaded. If organization retention or storage policy blocks upload, fix that policy or retrieve sanitized local reports; do not upload raw outputs as a workaround.
