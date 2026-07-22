# Consumer distribution

The bundle includes the strict project-capability schema, validator, questionnaire-enabled initializer, doctor support, and upgrade preservation logic. It does not carry VibeSec's own answers into a consumer repository. Consumers answer every `[Y/n]` question or provide a trusted local `--capabilities-file`; non-interactive EOF is rejected.

Consumer bundles declare `supported_addons: [dast-baseline]` and include the reviewed DAST runner, parser, configuration, policies, artifact validator, documentation, and workflow template. Install a base profile first, then preview and write `--addon dast-baseline`. The initializer remains offline and atomic; it never pulls the configured application image.

VibeSec development bundles are deterministic, consumer-only ZIP files. Build and verify one locally:

```shell
python3 scripts/build_consumer_bundle.py --output dist/vibesec-consumer.zip
python3 scripts/verify_consumer_bundle.py dist/vibesec-consumer.zip
```

An optional full lowercase commit SHA may be recorded with `--source-commit`. The version always comes from the strict UTF-8 `VERSION` file; no distribution command invokes Git or a network service.

The file set is selected only by `config/adoption-files.json`. It includes both profile support sets, workflow templates, policies, local Opengrep rules, distribution commands, offline documentation, the license, and security notices. It excludes tests, fixtures, Git data, caches, scanner binaries, vulnerability databases, dependencies, arbitrary untracked files, and prior artifacts.

## Determinism and format

Entries are sorted, use fixed timestamps and ZIP metadata, deterministic `0644` or reviewed `0755` modes, DEFLATE level 9, and canonical UTF-8 JSON. Source mtimes, working directory, umask, locale, host, user, and unrelated environment values are not recorded. `vibesec-bundle-manifest.json` records schema and format versions, development version, optional source commit, profiles, capabilities, network declaration, and each file's path, SHA-256, size, and mode.

Limits are 256 entries, 5 MB per entry, 25 MB compressed input, 25 MB total uncompressed content, 240 UTF-8 path bytes, and a 200:1 ratio check for entries larger than 1 MB. Only regular files and supported compression methods are accepted.

## Verification and initialization

Verification reads the ZIP without extracting it. It rejects traversal and alternate paths, links and special files, collisions, duplicate names or JSON keys, unsupported schemas or compression, excessive sizes or ratios, encryption, unexpected modes, missing or extra content, and any hash, size, catalog, version, or manifest mismatch.

Always verify a bundle before use, then initialize directly from it:

```shell
python3 scripts/init_vibesec.py --bundle dist/vibesec-consumer.zip --profile minimal --target /path/to/app
python3 scripts/init_vibesec.py --bundle dist/vibesec-consumer.zip --profile minimal --target /path/to/app --write
```

Standard remains two-stage: initialize `support`, merge reviewed support to the default branch, and then initialize `workflow`. Bundle and source-tree initialization share conflict, path, atomic-write, and rollback protections.

Development bundles are intentionally unsigned. Signing and provenance are deferred until a release process and durable identity policy exist. Verification proves internal format consistency, not publisher identity or application security. Do not extract or execute a suspicious bundle; preserve it privately if policy permits and report its source and verifier error through the security-reporting process.
