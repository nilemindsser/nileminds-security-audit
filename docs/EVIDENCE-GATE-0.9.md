# NMSA v0.9 — Evidence-first storage rules and review status

## Rule additions
- `nmsa.storage.public-blob-json-object`: static audit signal when a
  JSON-stringified payload is uploaded to Blob storage with public read access.
- `nmsa.node.cookie-http-only-disabled`: explicit `httpOnly:false` cookie
  configuration requiring review of whether it carries session/auth state.

These static signatures do **not** prove that sensitive data is in the
payload, that a Blob URL is publicly accessible, or that a cookie is an
authentication cookie. Confirm the data classification, ACL, and risk context.

## Independent evidence classification
`nmsa/evidence.py` supports:
`SCANNER_SIGNAL`, `NEEDS_VALIDATION`, `VALIDATED_IN_STAGING`,
`FALSE_POSITIVE`, `ACCEPTED_RISK`.

The default is SCANNER_SIGNAL. A claim of validation requires an explicit
reviewer, pinned revision, reproduction and impact references, non-production
environment, and a separate independent-verification flag. A human-reviewed
decision is required for false positive or accepted risk classification.

**Security limitations:** this is metadata validation, not signed or
cryptographically authenticated evidence. It cannot independently prove
reproduction or that a named reviewer actually performed it. No automatic
production clearance, remediation or skill activation occurs.

## Benchmark
Synthetic regression benchmark now covers eight targeted rule patterns,
with 16 small labeled cases (8 expected positives / 8 expected negatives).
Local result: TP=8 FP=0 FN=0 TN=8. These toy examples must NOT be used
as real-world precision/recall estimates.

## Independent verification still pending
- Staging-only controlled Blob tests with disposable data.
- Wider rules corpus and framework-specific positive/negative variations.
- API/tenant fixture tests for multiple roles, object IDs, pagination, export,
  and authenticated write paths (not safe for real systems without consent).
- Full external-skill sandbox certification and independent code review.
