# Contributing to VibeSec

Thank you for helping make practical security tooling easier to adopt.

## Before changing code

Open or reference an issue for changes that alter policy, scanner selection, result schemas, or workflow permissions. Explain the user need, security tradeoffs, and compatibility impact. Small documentation corrections may proceed directly.

## Development process

1. Branch from the latest `main`.
2. Keep changes small and reviewable; do not combine scanner upgrades with unrelated policy changes.
3. Run `python3 -m unittest discover -s tests -v`.
4. Validate YAML and run actionlint when available.
5. Run `python3 scripts/validate_repository.py`, `python3 scripts/validate_opengrep_rules.py`, and `python3 scripts/validate_skill.py skills/appsec-guardian` when their scope is changed.
6. Document verified upstream versions, licenses, checksums, signatures or image digests, network behavior, and overlap.
7. Add a changelog entry for user-visible behavior.

Scanner findings are untrusted input. Fixtures must be harmless, unmistakably fake, and must never contain usable credentials or offensive payloads. A suppression contribution must include a fingerprint, reason, owner, and expiration date. Never weaken an existing control silently.

Contributions are licensed under Apache-2.0. Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
