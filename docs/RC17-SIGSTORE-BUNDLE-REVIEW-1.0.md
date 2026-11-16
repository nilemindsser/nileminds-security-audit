# NMSA v1.0 RC17 — Offline Sigstore signed-blob gate

## Scope and trust boundaries

RC17 adds `python -m nmsa.sigstore_bundle_review` as a strict,
**non-authorizing** verifier for a locally signed blob and an on-disk
Sigstore bundle. The signer identity, OIDC issuer and trusted root are
independent policy inputs; the tool does not infer them from the
untrusted bundle and does not obtain a remote trust root.

This module is deliberately **not** the Docker image registry
signature verifier. A valid signature on an arbitrary blob is not
proof that a local Docker image, image manifest, or executable matches
the blob. Signature verification does not on its own approve a
publisher, software supply chain or production release.

## Command structure

```powershell
python -m nmsa.sigstore_bundle_review \
  --blob <local-signed-artifact> \
  --bundle <local-bundle.sigstore.json> \
  --trusted-root <independently-approved-trusted-root.json> \
  --certificate-identity <externally-approved-signer-identity> \
  --certificate-oidc-issuer <externally-approved-https-issuer>
```

The subprocess command is fixed to `cosign verify-blob` with
`--offline`, `--bundle`, `--trusted-root`,
`--certificate-identity`, and `--certificate-oidc-issuer`.
Arguments are passed without a shell. The module rejects missing,
empty, symlinked or oversized local files. It never returns raw
subprocess output, secret fields or local file paths. No installer,
image pull, container run, key creation or automatic network request
is implemented by the module.

If Cosign reports success, this is labeled
`SIGNED_BLOB_VERIFIED` and `signature_verified:true` **for that
blob only**, while `image_provenance_verified:false`,
`publisher_authorized:false`, `trusted_root_reviewed:false` and
`production_authorized:false` remain unchanged. There is no direct
release-gate promotion.

## Local findings — 2026-11-16

- `trivy` 0.76.2 exists on PATH.
- `cosign` and `syft` were not found on PATH.
- Trivy vulnerability database was past its documented NextUpdate;
  RC16 correctly retains its blocked status.
- No trusted signer policy, local Sigstore bundle or independent
  trusted root has been provided for this scope.
- Real signature verification was **NOT RUN**; no verified-signature
  claim should be made.
- All **159 local unit tests PASS** with Semgrep present.

## Remaining independent decisions

1. Approve the expected signature identity and OIDC issuer from a
   trustworthy channel other than the artifact being inspected.
2. Approve and verify the Sigstore trusted root and Cosign tool
   provenance/version before actual signature verification.
3. Obtain a matching on-disk signed artifact and its authentic bundle.
4. Separately verify the **Docker image manifest digest** and
   publisher's image signature/attestation; do not extrapolate from
   a signed arbitrary blob.
5. Review SBOM, vulnerability scan freshness, image source,
   Docker launcher persistence and overall NMSA security.
6. Obtain explicit owner authorization for release; external skills
   and production execution remain prohibited.

## References

- https://docs.sigstore.dev/quickstart/quickstart-cosign/
- https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-blob.md

**RC17 SOURCE CODE VALIDATED LOCALLY / TRUST CHAIN NOT VERIFIED /
PRODUCTION APPROVAL BLOCKED.**
