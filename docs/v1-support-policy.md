# VibeSec v1 support policy

VibeSec v1 supports its stable public contracts for the v1 major line. Reviewed scanner pins can receive compatible security and maintenance updates. Security fixes can reject newly recognized ambiguous or unsafe input, but they must preserve the documented failure category.

Complete native Minimal and Standard execution is validated on Linux x86_64. GitHub-hosted Ubuntu is the primary CI environment. Self-hosted runners must be Actions Runner 2.327.1 or newer and provide the documented Linux, Docker, storage, and network prerequisites.

Linux arm64 and macOS x86_64/arm64 can run the Python lifecycle, contract, documentation, and bundle commands. Complete native profile scanning is not claimed because the current inventory does not publish all checksum-pinned scanner artifacts for those platforms. The isolated Checkov, ZAP, and Schemathesis containers can run on Docker-capable supported CPU architectures, but that does not make a complete profile container available.

`native` is supported only for a complete validated host/profile combination. `container` remains unavailable for complete profiles. `auto` fails closed instead of selecting partial coverage.

Native Windows execution is not supported or claimed. WSL or an external Linux runner is a separate environment and must satisfy the Linux requirements. GitHub Enterprise Server support is not guaranteed: administrators must separately validate action availability, Node 24 runner compatibility, outbound access, artifact behavior, and OIDC/Sigstore availability. The release-signing identity in this repository is specific to GitHub.com.

DAST, API security, authenticated testing, fuzzing, image scanning, and OIDC signing remain conditionally enforced because they require explicit trusted inputs or environments. Live integrations are intentionally not required for untrusted pull requests.
