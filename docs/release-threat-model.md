# Release assurance threat model

## Assets and trust roots

The protected `main` commit, reviewed workflow, immutable GitHub Action pins,
official Cosign and Syft checksums, GitHub OIDC identity, Sigstore trust root,
deterministic bundle, manifest, SBOMs, provenance, and checksums are security
assets. The trust root must be obtained independently of the artifact set being
verified.

## Threats and controls

- A compromised upload or replaced bundle fails the signed checksum and strict
  manifest checks unless the signing identity or trust root is also compromised.
- A modified SBOM or provenance statement fails checksum, identity, and subject
  linkage. A different valid SBOM cannot silently replace the declared one.
- Mutable actions, tool URLs, tags, and image references are rejected or
  documented outside the signing path. Actions use full commits and tools use
  versioned URLs plus SHA-256.
- Fork and pull-request code cannot request OIDC, alter the trusted workflow, or
  be signed. There is no `pull_request_target` path.
- A compromised signing identity can sign malicious bytes. Exact certificate
  identity and issuer checks narrow but do not eliminate this risk; branch and
  workflow protection remain essential.
- Replayed attestations are detected only when the consumer compares the
  manifest version and source commit with the intended release. Cryptographic
  validity alone does not establish freshness.
- Offline consumers can validate checksums, manifest, provenance, and SBOM
  linkage without a network. Keyless signature verification requires separately
  authenticated Sigstore trust roots and may require cached transparency data.
- GitHub-hosted runners reduce persistent host state but remain a third-party
  trust dependency. Self-hosted runners may retain credentials or artifacts and
  must be ephemeral, patched, isolated, and restricted from untrusted jobs.

The workflow signs only artifacts produced in the same trusted job and uploads
only the closed release-candidate directory. It has no publication permission.
Raw scan results, credentials, runner paths, arbitrary refs, long-lived private
keys, and repository signing secrets are excluded.

Signatures attest identity and integrity, not benign behavior, correctness,
scanner completeness, vulnerability absence, or fitness for use.
