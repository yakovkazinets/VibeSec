# Agent upgrades

Run `vibesec agents upgrade-plan <adapter> --target . --json`. The command is read-only and reports installed and candidate versions, digest changes, installed state, and whether review is required.

VibeSec Guardian does not overwrite user-maintained instruction files during upgrade. Modified, missing, conflicting, disabled, local, or unsupported adapter state is preserved for human review. Disabled adapters stay disabled. Existing capability answers remain authoritative. Files outside the recorded adapter inventory are user-owned.

The consumer bundle includes the canonical contract, adapters, task pack, schemas, documentation, lifecycle module, and CLI. Bundle construction remains deterministic; verification hashes every included file. Applying a later adapter change requires a reviewed lifecycle operation rather than an implicit update during scan, doctor, or verification.
