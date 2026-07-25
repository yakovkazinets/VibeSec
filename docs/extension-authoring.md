# Extension authoring

The `agent-guidance` kind is reserved for reviewed first-party adapters. It may read trusted VibeSec contract and capability metadata, render in private staging, and write only its declared instruction path after explicit authorization. It must not execute scanners or agent CLIs, access secrets, use network or Docker, write arbitrary repository files, or override the canonical contract. Third-party v1 manifests remain `scanner` only.

An extension source directory contains `vibesec-extension.json`, its declared Python adapter, and only bounded regular files. Use `config/extension-manifest-schema.json` as a human-facing schema reference; runtime validation remains the authoritative strict parser.

The v1 manifest has exactly these keys: `schema_version`, `extension_id`, `version`, `kind`, `entrypoint`, `capabilities`, `supported_profiles`, `supported_platforms`, `execution_mode`, `network`, `artifacts`, and `permissions`. Only stable semantic versions and kind `scanner` are accepted. Capability names use `extension.<extension_id>.<lowercase-capability>`. Lists are sorted and unique.

V1 permission values are exact:

```json
{
  "repository_read": true,
  "repository_write": false,
  "network": false,
  "docker": false,
  "secrets": false,
  "host_process": true
}
```

The adapter receives one JSON object on stdin:

```json
{"schema_version":1,"repository_root":"/workspace","results_dir":"/private/results","profile":"minimal","capabilities":["extension.example.scanner.check"],"execution_mode":"native"}
```

It returns exactly `schema_version`, `exit_code`, `coverage`, `normalized_findings_path`, `artifacts`, and `diagnostics`. Exit codes are `0` completed without policy violation, `1` completed with a policy violation, `2` tool/runtime failure, and `3` invalid input. Failures use coverage `tool_error`. Diagnostics and output are bounded. Do not place raw source, request/response bodies, credentials, authorization headers, arbitrary environment values, or host paths in findings.

Use deterministic findings with stable rule IDs and fingerprints. Include an exact positive fixture, a negative fixture, and a controlled failure. Verify dry-run installation, installed-content verification, tamper detection, adapter exit preservation, bounded diagnostics, and bundle inclusion. The reference extension demonstrates the protocol without importing core modules.

The reserved future `agent-guidance` use case is intentionally not enabled by the v1 validator. Future Codex, Claude Code, Gemini, or Kimi integrations must extend the versioned kind contract without changing scanner semantics or granting secrets implicitly.
