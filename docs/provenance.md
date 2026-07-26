# Build provenance

`provenance.intoto.jsonl` is one canonical JSON in-toto Statement v1 using the
SLSA provenance v1 predicate type. Its four subjects are the consumer ZIP, both
SBOMs, and the exact-commit release-readiness record, each with an exact SHA-256
digest. Its build definition records the immutable
source repository and commit, development version, creation mode, and reviewed
Cosign and Syft versions. Run details record only the fixed release workflow
identity and a bounded invocation identifier.

The provenance intentionally omits wall-clock timestamps so identical trusted
inputs can produce identical unsigned metadata. Transparency material remains
in the separate Sigstore bundle. The strict verifier checks every subject
against the release manifest and checksum file and rejects unknown fields,
missing subjects, duplicate JSON keys, malformed digests, or a different
builder identity.

This is SLSA-aligned provenance preparation; VibeSec claims no SLSA level.
GitHub-hosted build isolation, branch policy, dependency integrity, and release
review must be evaluated separately. Consumers verify provenance with:

```shell
python3 /trusted/vibesec/scripts/verify_release_artifacts.py /path/to/release-set
```

The verifier also confirms that the CycloneDX 1.7 and SPDX 2.3 identities match
the distributed files and their manifest schema declarations. It does not
regenerate or modify SBOM contents for signing.
