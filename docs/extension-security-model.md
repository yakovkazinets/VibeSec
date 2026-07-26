# Extension security model

Extensions are executable code. Manifest validation and hashing establish structure and detect change; they do not prove that code is safe. Only install reviewed local sources from a trusted owner. VibeSec Guardian never discovers and runs project-provided extension directories automatically.

## Enforced v1 boundaries

- Strict UTF-8 JSON rejects duplicate keys, unknown fields, unsupported schema versions, ambiguous paths, traversal, and oversized inputs.
- Source collection rejects symlinks, non-regular files, collisions, oversized files, and unbounded trees.
- Scanner extensions require repository read and the declared adapter process. Repository write, network, Docker, and secrets are rejected.
- The core never imports adapter Python. It starts the exact hashed entrypoint in a subprocess with isolated Python mode, a private temporary directory, no inherited arbitrary environment, bounded time, and bounded stdout/stderr.
- The request contains only schema version, repository/results paths, profile, namespaced capabilities, and execution mode. It contains no secret.
- Output uses an exact JSON protocol. Process exit and declared exit must match. Exit `2` or `3` must be `tool_error`; malformed output becomes exit `2` and can never be clean.
- Only declared bounded artifacts are copied out of the private results directory. `normalized.json` must pass the core structural validator. Diagnostics redact bearer-shaped values.
- Installed bytes, modes, inventory, identity, permissions, and capability registrations are reverified before execution. Tampering blocks execution.

## Residual risks and limitations

The native subprocess boundary is not an OS sandbox. A malicious locally approved adapter could use operating-system APIs beyond its manifest declaration. The minimal environment and protocol reduce accidental exposure but cannot enforce filesystem or network isolation portably. V1 therefore allows only explicitly reviewed local sources and rejects network, Docker, secrets, and repository-write grants. Stronger native sandboxing and signed distribution are future work.

An extension can still emit misleading findings. VibeSec Guardian validates shape, bounds, provenance, and failure state; it does not prove scanner semantics. Passing extension scans does not prove application security. Never include secret-bearing raw output in declared artifacts.

Extension code cannot gain authority by changing its manifest after installation: any content change invalidates the inventory. Reinstalling or upgrading requires a new explicit review; no automatic remediation or marketplace trust is implemented.
