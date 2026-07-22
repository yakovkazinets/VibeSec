# GitHub Actions runtime and pin policy

VibeSec's supplied GitHub.com workflows use Node 24 JavaScript actions pinned to full commit SHAs. Node 20 is end-of-life and unsupported. VibeSec does not provide a compatibility override or fallback to an older action generation. GitHub-hosted runners satisfy the Node 24 action requirement; self-hosted runners must run Actions Runner 2.327.1 or newer. An older runner fails when it cannot launch a `node24` action and must be upgraded rather than bypassed.

VibeSec itself is a Python and shell project and owns no executable Node application or action. JavaScript and package manifests under `tests/` are inert scanner fixtures. Consumers do not need npm, a Node application runtime, `actions/setup-node`, or a Node build step. Node 26 is a future compatibility target, not a current requirement or support claim; the reviewed third-party actions embed Node 24.

## Reviewed action inventory

`config/github-actions.json` is the offline authority for the exact release, commit, embedded runtime, verification date, and minimum runner. Every adjacent workflow comment must agree with it.

| Action | Previous reviewed pin | Current reviewed pin | Exact runtime evidence | Runner and service notes | Security-relevant change |
|---|---|---|---|---|---|
| `actions/checkout` | v4.2.2, `11bd71901bbe5b1630ceea73d27597364c9af683`, Node 20 | v6.0.2, `de0fac2e4500dabe0009e67214ff5f5447ce83dd` | The [exact `action.yml`](https://github.com/actions/checkout/blob/de0fac2e4500dabe0009e67214ff5f5447ce83dd/action.yml) declares `runs.using: node24`; see the [official release](https://github.com/actions/checkout/releases/tag/v6.0.2). | Node 24 needs runner 2.327.1. Authenticated Git operations from a Docker container action need 2.329.0, but VibeSec neither persists checkout credentials nor performs that flow. Checkout accepts the current GitHub server URL. | v6 stores persisted credentials under `$RUNNER_TEMP` rather than `.git/config`. Every VibeSec checkout explicitly sets `persist-credentials: false`, so no credential is persisted; existing `fetch-depth` values are unchanged. |
| `actions/upload-artifact` | v4.6.2, `ea165f8d65b6e75b540449e92b4886f43607fa02`, Node 20 | v7.0.1, `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | The [exact `action.yml`](https://github.com/actions/upload-artifact/blob/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/action.yml) declares `runs.using: node24`; see the [official release](https://github.com/actions/upload-artifact/releases/tag/v7.0.1). | Node 24 needs runner 2.327.1. `upload-artifact@v4+` is not supported on GHES. | v7 can upload one file without an archive. VibeSec explicitly keeps `archive: true`, `include-hidden-files: false`, `if-no-files-found: error`, the existing 14-day retention, unique names, and the exact sanitized paths. Raw scanner results remain excluded. |

The supplied templates target GitHub.com. Their `upload-artifact@v7` pin is not a supported GHES path. Upstream identifies v3.2.2 as its Node 24 GHES line, but VibeSec does not distribute or validate a GHES-specific workflow. A GHES maintainer must separately review and maintain a full-SHA Node 24 path with equivalent artifact and credential controls; never silently substitute a Node 20 or deprecated action.

## Maintainer update procedure

1. Inventory every tracked action with `git grep -nE 'uses:[[:space:]]*[^[:space:]]+@'` and record current pin, release, and exact embedded runtime.
2. In the action's official repository, select a stable release, verify its signed or GitHub-verified release commit, and resolve the tag to a full lowercase 40-character SHA.
3. Inspect `action.yml` at that exact SHA and require `runs.using: node24`. Review release notes, runner minimum, GHES support, credential behavior, artifact behavior, and security-impacting defaults.
4. Update `config/github-actions.json`, every workflow/template/fixture reference, and its exact `# vX.Y.Z, Node 24, verified YYYY-MM-DD` comment. Preserve checkout depth, disabled credential persistence, artifact paths, retention, failure behavior, archiving, hidden-file exclusion, and sanitized-only upload boundaries.
5. Run the offline repository validator, full tests, bundle/install/doctor/upgrade lifecycle, syntax checks, and actionlint. Remote verification is a maintainer update activity; normal CI trusts the committed reviewed inventory and does not resolve tags over the network.

Do not set `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION=true`, enable another runtime override, or replace an immutable SHA with a tag. `validate` remains VibeSec's required aggregate job.
