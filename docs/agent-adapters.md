# Agent adapters

Machine objects: `vibesec.agent-adapter.codex.v1`, `vibesec.agent-adapter.claude-code.v1`, `vibesec.agent-adapter.gemini-cli.v1`, and `vibesec.agent-adapter.kimi-cli.v1` under `machine/agents/adapters/`.

Each built-in adapter has the same semantic sections: identity, authority, actions, safety, capabilities, validation, and tasks. Repository validation compares those sections, contract identity, task IDs, and required language so vendor-specific output cannot silently lose a safety rule.

The conventions were verified on 2026-07-24 against primary documentation:

- [OpenAI Codex AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md) reads one override or `AGENTS.md` per directory from repository root toward the working directory; nearer guidance wins.
- [Claude Code memory](https://code.claude.com/docs/en/memory) recognizes project `CLAUDE.md` and `.claude/CLAUDE.md` and supports imports. VibeSec uses the namespaced project location without imports.
- [Gemini CLI context files](https://google-gemini.github.io/gemini-cli/docs/cli/gemini-md.html) use `GEMINI.md` by default and compose context by scope. VibeSec uses the default project filename.
- [Kimi Code CLI agents](https://moonshotai.github.io/kimi-code/en/customization/agents.html) recognizes repository `AGENTS.md` and `.kimi-code/AGENTS.md`. VibeSec uses the namespaced location to avoid competing with Codex’s root file.

Adapters are deterministic text renderers, not tool integrations. VibeSec never starts these CLIs and does not inspect prompts, conversations, model configuration, tokens, or provider credentials.
