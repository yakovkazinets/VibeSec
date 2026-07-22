# Upgrading VibeSec

The planner classifies `.vibesec/project-capabilities.json` as `capability_preserve`. Existing answers, especially No, are never reset to Yes. If a future schema adds questions, interactive upgrades default those new questions to Yes, but non-interactive upgrades must supply explicit reviewed answers. No upgrade command silently infers answers from repository detection.

Finding-intelligence schemas and generators are additive consumer files. Existing scanner fingerprints, baselines, and suppressions remain valid. `policy/severity-thresholds.yml` is preservation-sensitive, so optional group controls require review instead of silent replacement.

The planner also classifies `.vibesec/authenticated-security-testing.json` as `capability_preserve`. Preserve only the validated GitHub secret name and fixed bearer metadata. A token value, hash, prefix, decoded claim, alternate header, or alternate scheme is never upgrade state. Review regenerated workflows so the exact static secret reference remains confined to the scanner step.

Upgrade planning treats `policy/dast-baseline.json` and `policy/dast-suppressions.json` as preservation-sensitive and never applies a plan. Review add-on workflow, image pins, isolation bounds, baseline, and suppressions manually with the version-compatible support set.

VibeSec has no destructive automatic upgrader and no `--apply` mode. Create a working branch, back up policy files and local modifications, verify a newer local bundle, and generate a read-only plan:

```shell
python3 scripts/verify_consumer_bundle.py /path/to/new-vibesec-consumer.zip
python3 scripts/plan_vibesec_upgrade.py --target /path/to/app --bundle /path/to/new-vibesec-consumer.zip
```

## v0.1.0 Minimal to current Minimal

Preserve `policy/baseline.json` and `policy/suppressions.yml`. Compare the workflow, pinned tools, normalization, result writer, policy gate, and `scripts/vibesec/` as a version-compatible set. Adopt the safer initializer manifest without overwriting existing files: preview against a clean temporary copy or compare files manually, then apply reviewed differences. Confirm the workflow still starts in the intended enforcement mode.

## v0.2.0 Standard to unreleased development

Post-v0.2.0 consumer hardening on `main` is unreleased development and does not add scanner categories or weaken v0.2.0 trust boundaries. Preserve `policy/standard-baseline.json` and suppressions. Review the initializer/catalog, diagnostics, documentation, and test changes alongside any workflow/support-file changes. Keep the base-revision harness, immutable pins, isolated results, no-secret fork behavior, and two-stage bootstrap intact.

## Node 20 action pins to Node 24

The planner identifies installed workflows that differ from the current bundle and proposes the reviewed full-SHA Node 24 workflow bytes without applying them. Doctor separately names the known v4.2.2 checkout and v4.6.2 artifact Node 20 pins. Preserve unrelated local workflow changes and merge the pin, exact review comment, `persist-credentials: false`, existing `fetch-depth`, artifact paths, 14-day retention, `if-no-files-found: error`, hidden-file exclusion, and archived upload settings manually. Before adoption, require self-hosted Actions Runner 2.327.1 or newer and review the [GitHub.com/GHES boundary](github-actions-runtime.md). Never resolve the migration by enabling a Node 20 fallback.

## Plan classifications

The planner compares manifest expectations, current bytes, and proposed bundle bytes. It reports `unchanged`, `add`, `upstream_changed_local_unmodified`, `locally_modified_upstream_unchanged`, `both_modified`, `remove_candidate`, `capability_preserve`, preservation-specific baseline/suppression states, `policy_review_required`, workflow/support mismatch, unknown legacy state, conflict, or unsafe path. `both_modified` always needs manual three-way review.

Preserve baselines, suppressions, user-modified policy and ignore files, and user-modified workflows. Review scanner and action pin changes against upstream records. Compare network behavior, OSV metadata transmission, registry access, SBOM retention, and artifact privacy before adoption. The plan contains no replacement commands and does not write the target.

## Review procedure

1. Record the installed VibeSec version and back up baselines, suppressions, and local configuration outside the working change.
2. Compare local files to the new release by path and content. Do not replace locally modified files blindly.
3. Review changed policy defaults and scanner versions against upstream release notes and verified checksums/signatures.
4. Keep workflows and support files from the same VibeSec version; a newer workflow with older scripts can fail closed or misreport coverage.
5. Test reviewed changes in a branch with `observe`, run repository/skill/rule validation, lint workflows, and inspect JSON/Markdown artifacts before merging.
6. Reconfirm network/privacy expectations, SBOM retention, fork behavior, and profile-specific baseline selection.

## Rollback

Revert the reviewed upgrade commit or restore the backed-up version-compatible file set. Restore baseline and suppression files only from the same repository and profile. Re-run in `observe` and verify reports before restoring enforcement. Never use an automatic force/overwrite command; rollback must remain reviewable. Destructive upgrades are deferred because local policy intent and trust-boundary changes cannot be merged safely without human judgment.

For API Security Baseline upgrades, preserve the explicit project capability answers, target configuration, `policy/api-security-baseline.json`, and `policy/api-security-suppressions.json`. Review the Schemathesis version/digest, exact CLI options, check-to-severity mapping, schema rules, request bounds, method opt-in, and isolation flags together. Never replace a local API policy or enable mutating methods automatically.
