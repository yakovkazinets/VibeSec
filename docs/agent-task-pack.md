# Agent task pack

Machine object: `vibesec.agent-capability-rules.v1` in `machine/agents/capabilities.json`. Each task is a closed object in `machine/agents/tasks/` and links back to this page.

The stable v1 task IDs are `security-audit`, `fix-security-findings`, `add-security-feature`, `upgrade-vibesec`, `validate-installation`, `review-extension`, `prepare-pull-request`, `resolve-ci-failure`, `resolve-merge-conflicts`, and `prepare-release-candidate`.

Every task declares an objective, scope, allowed actions, prohibited actions, required checks, failure handling, required evidence, expected output, and capability requirements. Render one without writing:

```sh
vibesec agents render-task codex resolve-ci-failure --target . --json
```

`.vibesec/project-capabilities.json` is authoritative. An explicit No is never overridden by file detection. DAST requires `web_application` and `dast_target`; API security requires `api`, `container_image`, and `api_security_target`; active fuzzing also requires `api_fuzzing_target`; authenticated testing requires `authentication` and `authenticated_security_testing`. When a required answer is false, that optional task is rendered as `suppressed`. If the manifest is absent, optional runtime tasks remain suppressed rather than being guessed into existence.
