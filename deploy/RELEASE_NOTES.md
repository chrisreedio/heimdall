## Verifying this release

Every file is listed in `SHA256SUMS`, which is signed with Sigstore (keyless, from this repository's release workflow).

```sh
# 1. Check the signature on the checksum list
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/chrisreedio/heimdall/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. Check the files you downloaded against it
sha256sum -c --ignore-missing SHA256SUMS

# Optional: verify build provenance
gh attestation verify heimdall-linux-amd64 --repo chrisreedio/heimdall
```

Binaries are reproducible: `make reproducible` at this tag builds the same bytes.
