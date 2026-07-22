# Upgrade with local policy changes

Verify the proposed local bundle and run `scripts/plan_vibesec_upgrade.py`. Treat baselines, suppressions, ignore files, policies, and workflows as preservation-sensitive. Explain `locally_modified_upstream_unchanged` and `both_modified`; the latter requires a manual three-way review.

Review scanner/action pins, security behavior, network metadata, and artifact privacy. Test selected changes in a branch under `observe`, retain rollback material, and never propose blind replacement or an apply/force command.
