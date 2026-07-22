# Release signing

The only prepared signing path is `.github/workflows/release-candidate.yml`.
It is manual, runs only for this repository on `refs/heads/main`, checks out and
verifies the exact dispatch commit, builds the deterministic bundle twice,
generates local SBOMs, creates provenance, signs only `SHA256SUMS`, verifies the
complete set, and uploads a short-lived release-candidate artifact. It does not
create a release, tag, package, commit, or push.

The signing job alone has `id-token: write`; repository contents remain read
only. No pull-request or `pull_request_target` event can reach the job. No
private key or signing secret is configured. Cosign 3.1.2 is pinned by official
release URL and SHA-256 in `config/tools.json`, licensed Apache-2.0, and was
reverified from the official Sigstore release on 2026-07-22. The Sigstore bundle
contains the ephemeral certificate, signature, and transparency evidence.
`scripts/sign_release_artifacts.py` independently requires the exact GitHub
Actions, workflow-dispatch, repository, `main` ref, and source-commit context;
it preserves Cosign failure as exit `2` and publishes no partial signature.

For a downloaded official set, first perform checksum and structural checks
using a separately trusted verifier:

```shell
python3 /trusted/vibesec/scripts/verify_release_artifacts.py /path/to/release-set
```

Then use a separately trusted checksum-verified Cosign binary and require the
reviewed GitHub workflow identity and issuer:

```shell
python3 /trusted/vibesec/scripts/verify_release_artifacts.py /path/to/release-set \
  --require-signature --cosign /trusted/bin/cosign \
  --certificate-identity 'https://github.com/yakovkazinets/VibeSec/.github/workflows/release-candidate.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

The equivalent direct signature check is:

```shell
/trusted/bin/cosign verify-blob \
  --bundle /path/to/release-set/SHA256SUMS.sigstore.json \
  --certificate-identity 'https://github.com/yakovkazinets/VibeSec/.github/workflows/release-candidate.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  /path/to/release-set/SHA256SUMS
```

Cosign verification may need Sigstore trust-root material. For disconnected
verification, provision and authenticate the required trust root separately
before going offline; the downloaded artifact directory is not its own trust
root. A replayed, correctly signed older artifact remains valid cryptographically,
so consumers must also compare the manifest version and full commit with the
intended release. Signing does not establish software safety.
