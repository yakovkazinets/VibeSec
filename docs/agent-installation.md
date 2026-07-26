# Agent installation and verification

List and inspect the built-ins:

```sh
vibesec agents list --json
vibesec agents describe codex --json
vibesec agents plan codex --target . --json
```

`plan` and `install` are dry runs by default. The only installation mutation is:

```sh
vibesec agents install codex --target . --write --json
```

The write creates exactly the adapter’s declared instruction file and `.vibesec/agents.json`. The inventory records adapter and contract versions, file path and SHA-256 digest, built-in source identity, portable platform compatibility, and enabled state. It never stores prompts, conversations, secrets, tokens, credentials, telemetry, or model configuration.

Existing instruction targets are never overwritten. The plan returns `conflicting`, marks `merge_required=true`, and stops so a maintainer can review and merge guidance manually. Symlinked or traversing targets, malformed inventories, duplicate IDs, and unsupported versions fail closed.

Use `vibesec agents verify <adapter>`, `vibesec agents doctor`, `vibesec agents disable <adapter> --write`, and `vibesec agents remove <adapter> --write`. Removal refuses modified or conflicting files. A disabled adapter remains installed and verifiable; no VibeSec Guardian operation invokes it or any external agent CLI.
