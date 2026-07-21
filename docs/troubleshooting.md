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
