# Troubleshooting

## No report was generated

Treat the run as a tool failure, not a clean scan. Inspect installation and scanner logs, confirm the runner is Linux x86_64, and verify GitHub release access. The artifact step intentionally fails when expected files are absent.

## Checksum verification failed

Stop. Do not update the checksum to match an unexpected file. Compare the configured release with the official upstream release page and checksum asset, then review release notes before changing both version and checksum together.

## Exit code interpretation

- `0`: evaluation completed without an enforced violation.
- `1`: policy violation.
- `2`: scanner or infrastructure failure.
- `3`: invalid policy or malformed scanner output.

## First adoption blocks too much

Keep `observe` mode, review the reports, remediate urgent issues, and baseline accepted historical findings before enabling `new`. Do not mass-suppress findings.

## actionlint reports the template expression syntax

Run the official actionlint binary against the exact workflow. YAML parsers alone do not understand GitHub expression semantics.

## Standard reports not applicable or not configured

Read `results/coverage.json` and `results/inventory.json`. `not_applicable` means supported repository evidence was not detected. `not_configured` means an optional input was absent or disallowed by the event. Neither is a pass. If detection missed a real artifact, add a harmless fixture and improve deterministic detection rather than forcing every scanner to run.

## OSV offline mode fails before scanning

Offline mode requires a database provisioned outside VibeSec, `VIBESEC_OSV_DATABASE_DIR=/path/to/database`, and `VIBESEC_OSV_DATABASE_DATE=YYYY-MM-DD`. Each ecosystem must contain a valid, nonempty `all.zip` with advisory JSON. The declared age must not exceed `VIBESEC_OSV_MAX_DATABASE_AGE_DAYS` (default `7`). VibeSec does not download or refresh that database because doing so would make offline behavior misleading. Online mode may send package names, versions, ecosystems, and file hashes to OSV.dev or deps.dev.

## Checkov cannot start

Confirm Docker is available and can pull the configured immutable digest. VibeSec does not fall back to a mutable tag or a network-enabled invocation. No IaC means Checkov should be `not_applicable`, not an error.

## SBOM validation fails

Both SBOM files must be valid, structurally identified, and contain packages/components. Empty, partial, or malformed output is not accepted as successful SBOM coverage. The starter stores the validated pair in a separate 14-day artifact because it can reveal internal package names and versions. Syft does not enrich packages, perform language metadata lookups, or check for updates.

## Prebuilt image scan is skipped

Image scanning runs only outside `pull_request` and only when `VIBESEC_IMAGE_REFERENCE` matches `registry/name@sha256:<64 lowercase hex characters>`. VibeSec never builds the Dockerfile and the starter workflow never injects registry credentials.
