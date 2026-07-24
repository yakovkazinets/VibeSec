# Platform support

`config/portable-execution.json` is the machine-readable support matrix. Platform IDs are `linux-amd64`, `linux-arm64`, `macos-amd64`, and `macos-arm64`.

| Platform | Native Minimal/Standard | Immutable complete-profile container | Current limitation |
|---|---|---|---|
| Linux x86_64 | Supported with the complete checksum-verified local tool set | Not distributed | Optional scanner containers remain capability-specific |
| Linux arm64 | Not yet supported | Not distributed | Native upstream artifacts are not pinned in this release |
| macOS x86_64 | Not yet supported | Not distributed | Current native scanner pins are Linux artifacts |
| macOS arm64 | Not yet supported | Not distributed | Current native scanner pins are Linux artifacts |

Checkov, Schemathesis, and ZAP use immutable capability-specific images and may run through their existing isolated workflows on Docker platforms. That does not make a complete profile container available. Support is never inferred from Docker merely being installed.

Windows-native execution is deferred. Docker Desktop on Windows may run independently supported immutable capability workflows, but the complete local CLI profile has not been tested or claimed. Path, permission, and executable semantics remain a limitation.

Portable Python handles platform detection, strict JSON, hashing, and extension lifecycle operations. Existing Bash scanner orchestration is used only where the platform matrix declares it. No BSD/macOS compatibility is claimed for Linux-only installers. GitHub Actions continues to use Node 24 actions and does not change these local platform claims.
