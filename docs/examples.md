# Tested v1 adoption examples

The machine source for these examples is [`machine/examples.json`](../machine/examples.json).
CI materializes every prerequisite in a disposable directory and executes all
eleven listed commands against local harmless fixtures. It verifies the exact
exit, checks that no fixture file changed during the documented dry-run or
read-only operation, and rejects credential, public-target, or operational
exploit content.

Run initializer examples without `--write` first. For add-on, doctor, extension,
agent, verification, and upgrade examples, CI first creates the required base
installation, local bundle, local schema, or unsigned local release candidate.
Those prerequisites are not implicit in the command itself. No example starts
an application, invokes a scanner, fetches a dependency, contacts a public
service, or uses a secret value.

For the authenticated API row, the disposable base installation is created
with `--auth-secret-name VIBESEC_TEST_TOKEN`; the add-on command intentionally
does not repeat that option because it is valid only while first creating the
project capability manifest. CI confirms the resulting configuration retains
that name and contains no token value.

<!-- BEGIN GENERATED EXAMPLES -->
| Pattern | Fixture | Validated commands |
|---|---|---|
| `vibesec.example.minimal-source` — Minimal source repository | `tests/consumer-fixtures/python-app` | `./vibesec init --profile minimal --target tests/consumer-fixtures/python-app --all-capabilities` |
| `vibesec.example.standard-application` — Standard application repository | `tests/consumer-fixtures/javascript-app` | `./vibesec init --profile standard --stage support --target tests/consumer-fixtures/javascript-app --all-capabilities` |
| `vibesec.example.containerized-web` — Containerized web application | `tests/consumer-fixtures/dockerfile-repo` | `python3 scripts/init_vibesec.py --addon dast-baseline --target tests/consumer-fixtures/dockerfile-repo` |
| `vibesec.example.openapi-api` — OpenAPI API | `tests/security-fixtures/api-security/positive` | `python3 scripts/init_vibesec.py --addon api-security-baseline --target tests/security-fixtures/api-security/positive --api-schema openapi.json` |
| `vibesec.example.authenticated-api` — Authenticated API whose base-installation prerequisite records a secret name but no value | `tests/security-fixtures/authenticated-security-testing/positive` | `python3 scripts/init_vibesec.py --addon api-security-baseline --target tests/security-fixtures/authenticated-security-testing/positive --api-schema openapi.json` |
| `vibesec.example.api-fuzzing` — Bounded opt-in API fuzzing | `tests/security-fixtures/api-fuzzing/positive` | `python3 scripts/init_vibesec.py --addon api-fuzzing --target tests/security-fixtures/api-fuzzing/positive --fuzzing-mode fuzz --fuzzing-enabled` |
| `vibesec.example.local-cli` — Read-only local CLI diagnostics | `tests/consumer-fixtures/python-app` | `./vibesec doctor --target tests/consumer-fixtures/python-app --json` |
| `vibesec.example.first-party-extension` — First-party repository metadata extension | `extensions/examples/repository-metadata` | `./vibesec extensions install extensions/examples/repository-metadata --target tests/consumer-fixtures/python-app --json` |
| `vibesec.example.multi-agent` — Codex multi-agent guidance preview | `tests/fixtures/agents/positive` | `./vibesec agents plan codex --target tests/fixtures/agents/positive --json` |
| `vibesec.example.release-verification` — Offline release candidate verification | `tests/security-fixtures/supply-chain` | `python3 scripts/verify_release_artifacts.py release-candidate --json` |
| `vibesec.example.upgrade` — Read-only upgrade plan from an existing installation | `tests/consumer-fixtures/existing-security-workflow` | `./vibesec upgrade-plan --target tests/consumer-fixtures/existing-security-workflow --bundle vibesec-consumer-bundle.zip --json` |
<!-- END GENERATED EXAMPLES -->
