# Partial Standard installation

Run `scripts/verify_installation.py` before scanner diagnostics. If only support is intentionally installed, explain the two-stage bootstrap and require that reviewed support land on the default branch before adding the workflow. If a workflow exists without its support manifest/files, classify it as an installation error, not a vulnerability or clean scan.

Use `scripts/vibesec_doctor.py --profile standard` for redacted diagnostics. Do not print environment values, install tools, overwrite files, or weaken the base-revision harness. Repair the matching versioned support set through a reviewed branch.
