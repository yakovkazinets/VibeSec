# Local execution

The reviewed `./vibesec` CLI can install a complete verified profile toolchain and run the canonical profile without modifying the target repository:

```shell
./vibesec scan \
  --profile standard \
  --target /path/to/repository \
  --install-tools \
  --json
```

`--install-tools` selects managed native mode. `--cache-dir` overrides `VIBESEC_CACHE_HOME`; `--results` overrides the opaque repository result location; `--network-mode online|offline` controls Standard OSV behavior. Existing callers may still provide `--tool-dir` without managed installation. Combining `--tool-dir` and `--install-tools` is invalid.

The default cache is `~/Library/Caches/vibesec` on macOS and `${XDG_CACHE_HOME:-~/.cache}/vibesec` on Linux:

```text
<cache>/tools/<development-version>/<platform>/<profile>/
<cache>/runtime/<release-version>/
<cache>/results/<opaque-repository-id>/latest/
```

Executables and results stay outside the application repository. Managed mode validates the target, platform, complete cache, and result boundary; removes target directories from executable selection; runs exact cached scanner paths; and preserves `0` success, `1` policy violation, `2` tool failure, `3` invalid input, and `4` CLI/bootstrap infrastructure failure. It never retries through an unverified mode or converts installation/scanner failure into clean success.

Minimal runs Trivy filesystem, Gitleaks, and actionlint when workflow files exist. Standard adds the trusted local Opengrep rules, OSV source scanning, Syft CycloneDX/SPDX generation, conditional Checkov, deterministic normalization, coverage, policy, groups, and priority. Image scanning remains off unless a trusted context supplies an immutable digest. No profile installs project dependencies, runs lifecycle scripts or application code, builds the application or Dockerfiles, applies IaC, or performs remediation.

Raw outputs and scanner homes live in private temporary directories and are deleted on success or failure. Persisted artifacts are sanitized. Standard online mode can send package identifiers, versions, ecosystems, and file hashes to OSV.dev or deps.dev. Offline mode requires an explicit validated local OSV database.

For an installed skill with no VibeSec Guardian checkout, use the natural-language command documented in the [Quick Start](quickstart.md). The skill verifies a pinned consumer runtime before invoking this same managed CLI. CI installation is separate.

Execution modes remain `native`, `container`, and `auto`. A complete Minimal or Standard profile container is not distributed. See [platform support](platform-support.md), [tool selection](tool-selection.md), and [troubleshooting](troubleshooting.md).
