# Multi-agent support

Machine object: `vibesec.agent-documentation-map.v1` in `machine/agents/documentation-map.json`.

VibeSec provides one vendor-neutral safety and workflow contract with deterministic adapters for OpenAI Codex, Claude Code, Gemini CLI, and Kimi Code CLI. An adapter translates the same reviewed semantics into an instruction file that the selected tool discovers; it does not give the tool new authority and does not invoke the tool.

The built-in adapters are:

| Adapter ID | Tool | Generated project file |
| --- | --- | --- |
| `codex` | OpenAI Codex | `AGENTS.md` |
| `claude-code` | Claude Code | `.claude/CLAUDE.md` |
| `gemini-cli` | Gemini CLI | `GEMINI.md` |
| `kimi-cli` | Kimi Code CLI | `.kimi-code/AGENTS.md` |

The machine-readable source of truth lives under `machine/agents/`. `contract.json` defines authority, actions, validation, exit codes, coverage, and shared safety rules. `adapters/` records each verified official convention. `tasks/` contains the ten stable v1 task templates. `capabilities.json`, `safety-rules.json`, and `documentation-map.json` make applicability, threat boundaries, and human documentation traceable.

Start with `vibesec agents list --json`, inspect `vibesec agents describe <adapter> --json`, then run `vibesec agents plan <adapter> --target <repository> --json`. Installation is a dry run unless `--write` is present. If the destination already exists, VibeSec reports `conflicting`, generates a merge plan, and stops. It never appends, merges, or overwrites an existing instruction file.

VibeSec installation, rendering, verification, doctor, disable, removal, and upgrade planning are offline. They do not call agent CLIs, cloud APIs, telemetry endpoints, model providers, or credential stores. Generated guidance is advisory context: repository permissions, CI controls, branch protection, review, and human authorization remain the enforcement boundary.

See [agent installation](agent-installation.md), [contract](agent-contract.md), [adapters](agent-adapters.md), [task pack](agent-task-pack.md), [safety model](agent-safety-model.md), and [upgrades](agent-upgrades.md).
