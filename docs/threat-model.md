# Threat Model

## Assets and trust boundaries

Assets include repository source, workflow tokens, scanner reports, policy decisions, dependency metadata, and maintainer trust. Boundaries exist between pull-request content and trusted branch configuration, GitHub-hosted runners and upstream releases, scanners and normalization logic, and reports and human reviewers.

## Principal threats and controls

- A compromised action can steal a workflow token. Third-party actions are pinned to full commit SHAs and checkout does not persist credentials.
- A compromised scanner release can execute code. Scanner archives use versioned HTTPS URLs and verified upstream SHA-256 checksums.
- An untrusted pull request can manipulate context values or workflow files. The workflow uses `pull_request`, never `pull_request_target`, grants only `contents: read`, passes no secrets, and does not interpolate PR titles, branch names, or other untrusted context into shell code.
- Scanner output can contain malicious text, terminal controls, oversized content, paths, or discovered secrets. Output is treated as untrusted, normalized to a strict schema, secret values are discarded, and summaries apply defensive redaction.
- A failed scanner can appear clean. Execution errors become `tool_error` results and use a distinct failure exit code.
- Historical findings can prevent adoption. The default is observation; reviewed fingerprints can be baselined before `new` enforcement.
- Suppressions can become permanent blind spots. Each requires a reason, owner, and expiration date; expired suppressions reactivate findings.
- DAST can damage a live service. DAST is not implemented and must not target production by default in future profiles.
- Parser differentials can make two consumers assign different meaning to one imported skill. Duplicate YAML keys, aliases, anchors, custom tags, implicit booleans, unexpected types, excessive nesting, repeated front matter, malformed fences, and competing skill definitions fail closed under one strict schema.
- Encoding and display controls can hide or change instructions. UTF-8 BOMs, invalid UTF-8, bidirectional controls, and unexpected zero-width characters are rejected; line endings and Unicode are canonicalized to LF and NFC before hashing.
- Filesystem canonicalization can redirect references. Parent traversal, missing files, excessive path depth, case or normalization collisions, non-ASCII v0.1 skill paths, broken symlinks, and symlinks resolving outside the canonical root are rejected.
- Markdown can hide instruction-like content in examples, quotes, code fences, fixtures, or HTML comments. These regions—and all imported body text—remain non-authoritative data. Unclosed or nested fences and unclosed comments fail validation.
- Oversized packages can exhaust parser resources. Skill, reference, total-size, file-count, and path-depth limits are enforced before interpretation.

## Residual risk

Pins can reference an already-compromised upstream commit, checksums attest bytes rather than benign behavior, hosted runners and vulnerability databases can fail, scanners have false positives and false negatives, and no application build or runtime behavior is analyzed. Reviews must consider these limitations.

Unicode homoglyph detection is conservative in v0.1: non-ASCII package paths are rejected, but natural-language body text is not subjected to a full confusable-character database. Semantic Markdown interpretation may still differ across renderers, so ambiguous structures fail closed and imported prose never receives authority from parsing alone.
