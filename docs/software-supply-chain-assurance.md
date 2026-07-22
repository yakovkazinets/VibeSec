# Software supply-chain assurance

VibeSec prepares a closed, versioned release-candidate set without publishing
it. The set is exactly:

```text
vibesec-consumer-bundle.zip
sbom.cyclonedx.json
sbom.spdx.json
provenance.intoto.jsonl
release-manifest.json
SHA256SUMS
SHA256SUMS.sigstore.json
```

The deterministic consumer ZIP remains the distributable product. The two
SBOMs, SLSA-aligned provenance, release manifest, checksum list, and Sigstore
bundle are external assurance metadata so timestamps and transparency-log
material cannot make the ZIP non-reproducible. `release-manifest.json` records
the version, full source commit, closed artifact names, SHA-256 digests, sizes,
media types, schema versions, reviewed tool versions, creation mode, and
provenance linkage. It contains no runner path, secret, or mutable URL.

`scripts/prepare_release_artifacts.py` strictly validates the existing ZIP and
SBOM identities before writing metadata. `scripts/verify_release_artifacts.py`
strictly parses canonical JSON, rejects duplicate keys, unknown or missing
files, links, oversized inputs, wrong subjects, digest mismatch, bundle
identity mismatch, and malformed signature bundles. Checksum-only verification
is offline. Signature verification additionally requires a trusted external
Cosign executable and the exact certificate identity and issuer in
`config/supply-chain-policy.json`.

Normal Minimal, Standard, DAST, API, and authenticated scans never sign and do
not require network access for signing. Binary tools are never committed to the
repository or consumer bundle. Release tools are downloaded only by the manual
trusted workflow, from versioned official URLs, and checked against reviewed
SHA-256 pins before publication into the tool directory.

The offline posture validator checks immutable actions, least permissions,
manual trusted release triggering, source identity, security and dependency
policy documentation, provenance/signing controls, and the no-publication
boundary. It is an OpenSSF Scorecard-aligned local control review, not an
OpenSSF score and not a substitute for branch protection configured on GitHub.
Branch protection must require the aggregate `validate` check, review, and
restricted release authority; repository settings remain outside this source
tree validator.

Signing proves that the declared identity signed bytes whose digests match the
metadata. It does not prove that VibeSec is safe, free of vulnerabilities, or
appropriate for a consumer's environment.

## Bootstrap trust

Obtain the verifier and expected identity from a separately trusted VibeSec
source checkout or independently reviewed copy. Do not execute a script from
inside an unverified downloaded bundle as the first verification step. Pin or
verify Cosign through its official Sigstore release process, then run the
commands in [release signing](release-signing.md). Preserve release metadata
with the installed version for later doctor and upgrade review.

## OpenSSF posture

Repository maintainers should enable protected default branches, required
review, the `validate` check, private vulnerability reporting, Dependabot or an
equivalent reviewed dependency-update process, and least-privilege Actions
tokens in GitHub settings. The source tree enforces full action commit pins,
documents vulnerability reporting and release review, prohibits binary blobs,
and prepares provenance and signed artifacts. External Scorecard availability
does not block required CI; `scripts/validate_supply_chain_posture.py` is fully
offline and deterministic.
