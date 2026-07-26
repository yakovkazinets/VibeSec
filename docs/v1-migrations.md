# VibeSec v1 migrations

Use a verified local consumer bundle and run `./vibesec upgrade-plan --target <repository> --bundle <bundle.zip> --json`. The planner is read-only. It reports conflicts and never silently overwrites them.

The v1 migration contract covers representative v0.1.0, v0.2.0, current pre-v1, Minimal-only, Standard, DAST, API, authenticated, fuzzing, extension, and multi-agent installations. Machine records live in [`machine/migrations.json`](../machine/migrations.json).

CI materializes every one of those eleven records as a disposable local
installation, including the declared profile or add-on, explicit capability
answers, locally changed baseline, suppression and workflow files, a disabled
extension and agent adapter, user-authored agent guidance, a secret name
without a secret value, and an unrelated application file. It executes the
real upgrade planner for every installation, verifies the declared exit,
classification and inventories, and compares every file digest before and
after to prove the plan stayed read-only.

Every path preserves explicit capability answers, including explicit No answers; profile baselines and suppressions; locally customized workflows; user-authored agent files; installed and disabled extension or adapter states; secret names but never secret values; and unrelated repository files. A conflicting VibeSec-owned destination is a review result, not permission to replace local content.

For legacy installations without complete provenance metadata, first run doctor and installation verification. Treat missing release metadata as a warning requiring review, not proof of corruption. Back up the repository, review the entire plan, apply only intended changes, and rerun verification and the selected profile.
