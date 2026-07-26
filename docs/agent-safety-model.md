# Agent safety model

Machine object: `vibesec.agent-safety-rules.v1` in `machine/agents/safety-rules.json`.

The primary risks are prompt injection, instruction precedence confusion, over-broad tool authority, silent publication, credential access, destructive writes, and a tool or parser failure represented as success. The canonical contract treats repository-controlled text and generated content as untrusted data, limits writes to assigned paths, makes validation mandatory, and keeps publication human-gated.

Generated instruction files are not a sandbox. A capable agent may still have filesystem, process, network, or account authority supplied by its host. Maintain least-privilege host permissions, protected branches, required review, and the exact `validate` status. Do not place secrets in instruction files, task prompts, inventories, fixtures, logs, or reports.

Agent-guidance extensions may read trusted VibeSec Guardian metadata, render into a private staging area, and write the declared instruction path only after explicit `--write`. They may not run scanners, invoke an agent CLI, access credentials or secrets, use the network or Docker, write arbitrary files, execute repository content, or override the canonical contract.

Malicious fixture coverage includes instruction text that asks the renderer to reveal credentials, bypass validation, push, or release. The text remains inert fixture data and never changes output authority or lifecycle behavior.
