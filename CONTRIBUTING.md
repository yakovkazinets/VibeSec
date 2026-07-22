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

## Security capability accountability

Any change to a scanner, rule, profile, normalization, policy behavior, coverage state, artifact generation, scanner configuration, or trusted-event behavior must update `config/security-capabilities.json`, positive and negative fixtures, exact expected metadata, CI enforcement, documentation, controlled tool-error regressions, and applicable trust-boundary tests. Run `python3 scripts/validate_security_capabilities.py` and the complete suite. A capability is not complete because integration code exists.

A scanner version bump must record the old and new version, checksum/signature or image-digest verification, fixture-result changes, normalized-schema changes, runtime changes, network/privacy changes, new false positives, removed findings, and a documented review conclusion. Review expected count or severity changes; never weaken them merely to make CI pass. See [security validation policy](docs/security-validation-policy.md).

Contributions are licensed under Apache-2.0. Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
