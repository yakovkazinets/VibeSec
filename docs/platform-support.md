# Platform support

`config/portable-execution.json` is the machine-readable support matrix. The installer, CLI, verification, doctor, documentation, and tests share the deterministic IDs `linux-amd64`, `linux-arm64`, `macos-amd64`, and `macos-arm64`.

| Platform | Native Minimal/Standard | Complete-profile container | Current limitation |
|---|---|---|---|
| Linux x86_64 | Supported with exact verified native assets | Not distributed | Optional capability containers remain separate |
| macOS arm64 | Supported; primary v1.1 local acceptance platform | Not distributed | Checkov needs Docker only when supported IaC is applicable |
| macOS x86_64 | Supported with official verified native assets | Not distributed | Real-tool acceptance is secondary to macOS arm64 |
| Linux arm64 | Not supported in v1.1 | Not distributed | The complete release set is not yet reviewed as a supported profile |

The native set is Trivy 0.72.0, Gitleaks 8.30.1, actionlint 1.7.12, Opengrep 1.25.0, OSV-Scanner 2.4.0, Syft 1.49.0, and Cosign 3.1.2. `config/tools.json` pins every supported asset name, exact GitHub release URL, SHA-256, archive type, and executable. Opengrep also requires its upstream Sigstore certificate and signature with the exact reviewed workflow identity.

Managed installation uses Python `hashlib`, safe archive extraction, private staging, and atomic profile publication. It never uses Homebrew, a global npm/pip install, `curl | sh`, a floating tag, a target URL, or PATH fallback. A cache is accepted only when its manifest, versions, asset hashes, executable hashes, modes, platform, and profile all match.

Checkov remains an immutable digest-pinned container. When IaC is applicable and Docker is unavailable, coverage is `tool_error` and the scan is non-clean. Checkov, Schemathesis, and ZAP container support does not imply a complete profile container.

Windows-native execution is deferred. WSL is a separate Linux environment and must meet a supported Linux profile. GitHub Actions continues to use full-SHA Node 24 actions; this local scanner runtime does not require Node.js.
