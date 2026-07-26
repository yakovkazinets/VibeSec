# Local verified extensions

VibeSec Guardian also ships first-party, non-executing `agent-guidance` adapters backed by the canonical contract under `machine/agents/`. They use the same dry-run, explicit-write, inventory, digest, conflict, verification, disable, removal, and upgrade principles where applicable, but never run scanner or agent code. See [multi-agent support](multi-agent-support.md).

VibeSec Guardian v1 extension support is local-only. There is no marketplace, automatic download, registry publication, or automatic upgrade. An extension is untrusted until a maintainer reviews a local source directory, previews installation, explicitly uses `--write`, and verifies the installed digest inventory.

```shell
./vibesec extensions install ./extensions/examples/repository-metadata --target /path/to/repository --json
./vibesec extensions install ./extensions/examples/repository-metadata --target /path/to/repository --write --json
./vibesec extensions list --target /path/to/repository --json
./vibesec extensions describe vibesec.repository-metadata-example --target /path/to/repository --json
./vibesec extensions verify --target /path/to/repository --json
./vibesec extensions run vibesec.repository-metadata-example --target /path/to/repository --repository /path/to/repository --results /private/results --json
./vibesec extensions disable vibesec.repository-metadata-example --target /path/to/repository --write --json
./vibesec extensions upgrade-plan ./candidate --target /path/to/repository --json
./vibesec extensions remove vibesec.repository-metadata-example --target /path/to/repository --write --json
```

Mutations are dry-run by default. Installation refuses overwrite and symlinks, copies through private staging, publishes atomically, and records every installed path, mode, SHA-256, manifest digest, whole-content digest, source, permission grant, capability registration, version, enabled state, and an explicit null signature slot. Signature verification is not implemented in v1. Disable and removal preserve explicit intent; upgrades are plans only.

The bundled `vibesec.repository-metadata-example` scanner is a harmless reference contract. It needs repository read and one declared host adapter process, no network, secrets, writes, or Docker. Its positive fixture uses `.vibesec-example-positive`; its negative fixture is clean. It is not a replacement for any core scanner and is not installed automatically.

Extensions cannot replace core policy, schemas, baselines, validators, or capabilities. Registered capabilities must use `extension.<extension_id>.<capability>`. Core required CI never depends on an unbundled third-party extension.
