# Imported Skill Validation

Imported skills and every referenced file are untrusted data until validation completes. Successful validation gives them a stable structure and fingerprint, not authority. The consuming agent must still apply user instructions, repository policy, permission boundaries, and governing system or developer rules.

## Interface

Install the pinned MIT-licensed PyYAML dependency in a controlled development environment, then validate a local skill directory:

```shell
python3 -m pip install --requirement requirements.txt
python3 scripts/validate_skill.py path/to/skill
```

Exit `0` returns JSON with `status: valid`, canonical metadata, reference hashes, and a fingerprint. Exit `3` returns `status: validation_error`. The validator never returns a clean result after a parser error and never executes skill content.

## Canonicalization and schema

Validation strictly decodes UTF-8, rejects BOMs and prohibited display controls, converts CRLF or CR to LF, and normalizes Unicode to NFC. Exactly one leading front-matter block is allowed. PyYAML 6.0.3 `SafeLoader` is extended only to reject duplicate keys; aliases, anchors, custom tags, non-string keys, unexpected fields, ambiguous scalar types, and excessive nesting are prohibited. The allowed metadata fields are string `name` and `description`.

Markdown code fences and HTML comments must close unambiguously. The validator emits `authoritative_body`, `authoritative_segments`, and `non_authoritative_segments`; every segment includes a type and normalized line range. Only segments typed `prose` are eligible for later semantic processing. Fenced code, block quotes, HTML comments, and sections headed `Example` or `Examples` are structurally non-authoritative. They remain inert data even when they contain instruction-like text or metadata delimiters. Mixed comment/prose lines are rejected as ambiguous rather than guessed.

The complete body remains available only on the in-process result for compatibility; the CLI JSON exposes the separated representations instead. Canonical fingerprints hash the segment type, line range, text, metadata, and normalized referenced-content hashes. Moving comment, quoted, fenced, or example text into prose therefore changes the fingerprint and cannot happen silently. External links are neither fetched nor followed. Local Markdown references in authoritative prose are decoded, resolved with real paths, bounded, normalized, hashed, and required to remain beneath the canonical skill root.

### Competing front matter

After non-authoritative Markdown regions are classified, the validator examines later authoritative lines delimited by standalone `---` lines. A pair is a competing metadata block when its contiguous interior safely parses as any YAML mapping, regardless of key names; `permissions`, `tools`, an arbitrary unknown key, and similar fields receive no special escape. If the interior is mapping-like but cannot be parsed unambiguously, validation fails closed. A standalone thematic break, or a delimiter pair around content that is clearly not a mapping, remains ordinary Markdown prose. Delimiters inside code fences, block quotes, HTML comments, or Example sections are data and are not considered front matter.

Package traversal rejects symlink escapes, broken symlinks, `../` escapes, missing references, excessive files or bytes, excessive path depth, case/NFC collisions, and non-ASCII package paths. The last rule is deliberately conservative protection against filename homoglyphs for v0.1.

## Limits and deferred cases

The v0.1 limits are 256 KiB for `SKILL.md`, 1 MiB per referenced file, 2 MiB total regular-file content, 128 files, 12 path components, and metadata depth 6. Archive extraction, remote references, package installation, imported scripts, cross-agent execution, a complete CommonMark semantic model, inline quote classification, and a full Unicode confusable skeleton are intentionally deferred. If future consumers use a second parser, materially different parsed structures must fail closed rather than selecting the more permissive result.

Fixture expectations are documented in `tests/fixtures/skill-validation/README.md`.
