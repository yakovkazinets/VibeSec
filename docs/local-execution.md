# Local execution

The executable `./vibesec` is the first-class local entry point. It routes to the existing initializer, verifier, doctor, upgrade planner, Minimal runner, and Standard runner; it does not duplicate scanner or policy logic.

```shell
./vibesec scan --profile minimal --execution-mode auto --target /path/to/repository --results /private/results --json
./vibesec doctor --target /path/to/repository --json
./vibesec verify --target /path/to/repository --json
./vibesec init --profile minimal --target /path/to/repository
./vibesec upgrade-plan --target /path/to/repository --bundle /path/to/verified.zip --json
```

Execution modes are `native`, `container`, and `auto`. Native requires the complete regular executable tool set for the selected profile. Container requires a complete immutable profile image set. Auto selects a complete supported mode deterministically and reports the decision. It never retries a failed verified mode through a different or unverified mode.

The current release has complete native profile pins only for Linux x86_64. It has immutable container scanners for some optional capabilities, but does not distribute a complete Minimal or Standard profile container. Container mode therefore fails explicitly rather than claiming partial coverage. Scanner and parser exit codes remain `0` success, `1` policy violation, `2` tool failure, and `3` invalid input. CLI infrastructure failure remains `4`.

Local execution never installs project dependencies. Paths are resolved before use, scanner diagnostics are bounded, and JSON output is available with `--json`. A selected scanner mode that later fails is reported as failure; there is no fallback that could erase evidence.

GitHub workflows remain the authoritative CI examples and retain their full-SHA Node 24 actions. The local CLI does not require Node.js.
