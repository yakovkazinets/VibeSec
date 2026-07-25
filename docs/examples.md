# Tested v1 adoption examples

The machine source for these examples is [`machine/examples.json`](../machine/examples.json). CI validates all fixture paths, commands, schema references, and safety restrictions. Examples use only local harmless fixtures; they contain no credentials, public targets, or operational exploit payloads.

Run initializer examples without `--write` first. Commands that require a built bundle, installed extension, installed agent adapter, live Docker target, or release candidate are validation examples and document the required local input; they do not fetch or contact a public service.

<!-- BEGIN GENERATED EXAMPLES -->
| Pattern | Fixture | Validated commands |
|---|---|---|
| `vibesec.example.minimal-source` — Minimal source repository | `tests/consumer-fixtures/python-app` | `./vibesec init --profile minimal --target tests/consumer-fixtures/python-app --all-capabilities` |
| `vibesec.example.standard-application` — Standard application repository | `tests/consumer-fixtures/javascript-app` | `./vibesec init --profile standard --stage support --target tests/consumer-fixtures/javascript-app --all-capabilities` |
| `vibesec.example.containerized-web` — Containerized web application | `tests/consumer-fixtures/dockerfile-repo` | `python3 scripts/init_vibesec.py --addon dast-baseline --target tests/consumer-fixtures/dockerfile-repo --all-capabilities` |
| `vibesec.example.openapi-api` — OpenAPI API | `tests/security-fixtures/api-security/positive` | `python3 scripts/init_vibesec.py --addon api-security-baseline --target tests/security-fixtures/api-security/positive --api-schema openapi.json --all-capabilities` |
| `vibesec.example.authenticated-api` — Authenticated API using a secret name but no secret value | `tests/security-fixtures/authenticated-security-testing/positive` | `python3 scripts/init_vibesec.py --addon api-security-baseline --target tests/security-fixtures/authenticated-security-testing/positive --api-schema openapi.json --auth-secret-name VIBESEC_TEST_TOKEN --all-capabilities` |
| `vibesec.example.api-fuzzing` — Bounded opt-in API fuzzing | `tests/security-fixtures/api-fuzzing/positive` | `python3 scripts/init_vibesec.py --addon api-fuzzing --target tests/security-fixtures/api-fuzzing/positive --fuzzing-mode fuzz --fuzzing-enabled --all-capabilities` |
| `vibesec.example.local-cli` — Read-only local CLI diagnostics | `tests/consumer-fixtures/python-app` | `./vibesec doctor --target tests/consumer-fixtures/python-app --json` |
| `vibesec.example.first-party-extension` — First-party repository metadata extension | `extensions/examples/repository-metadata` | `./vibesec extensions install extensions/examples/repository-metadata --target tests/consumer-fixtures/python-app --json` |
| `vibesec.example.multi-agent` — Codex multi-agent guidance preview | `tests/fixtures/agents/positive` | `./vibesec agents plan codex --target tests/fixtures/agents/positive --json` |
| `vibesec.example.release-verification` — Offline release candidate verification | `tests/security-fixtures/supply-chain` | `python3 scripts/verify_release_artifacts.py release-candidate --json` |
| `vibesec.example.upgrade` — Read-only upgrade plan from an existing installation | `tests/consumer-fixtures/existing-security-workflow` | `./vibesec upgrade-plan --target tests/consumer-fixtures/existing-security-workflow --bundle vibesec-consumer-bundle.zip --json` |
<!-- END GENERATED EXAMPLES -->
