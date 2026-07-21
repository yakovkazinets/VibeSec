# Upgrading VibeSec

VibeSec has no destructive automatic upgrader. Back up policy files and local modifications, compare every installed path from `.vibesec/install-*.json` (or `config/adoption-files.json` for older installs), and review changes before replacement.

## v0.1.0 Minimal to current Minimal

Preserve `policy/baseline.json` and `policy/suppressions.yml`. Compare the workflow, pinned tools, normalization, result writer, policy gate, and `scripts/vibesec/` as a version-compatible set. Adopt the safer initializer manifest without overwriting existing files: preview against a clean temporary copy or compare files manually, then apply reviewed differences. Confirm the workflow still starts in the intended enforcement mode.

## v0.2.0 Standard to v0.2.1

v0.2.1 consumer hardening does not add scanner categories or weaken v0.2.0 trust boundaries. Preserve `policy/standard-baseline.json` and suppressions. Review the initializer/catalog, diagnostics, documentation, and test changes alongside any workflow/support-file changes. Keep the base-revision harness, immutable pins, isolated results, no-secret fork behavior, and two-stage bootstrap intact.

## Review procedure

1. Record the installed VibeSec version and back up baselines, suppressions, and local configuration outside the working change.
2. Compare local files to the new release by path and content. Do not replace locally modified files blindly.
3. Review changed policy defaults and scanner versions against upstream release notes and verified checksums/signatures.
4. Keep workflows and support files from the same VibeSec version; a newer workflow with older scripts can fail closed or misreport coverage.
5. Test in a branch with `observe`, run repository/skill/rule validation, lint workflows, and inspect JSON/Markdown artifacts before merging.
6. Reconfirm network/privacy expectations, SBOM retention, fork behavior, and profile-specific baseline selection.

## Rollback

Revert the reviewed upgrade commit or restore the backed-up version-compatible file set. Restore baseline and suppression files only from the same repository and profile. Re-run in `observe` and verify reports before restoring enforcement. Never use an automatic force/overwrite command; rollback must remain reviewable.
