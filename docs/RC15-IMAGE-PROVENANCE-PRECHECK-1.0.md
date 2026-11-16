# NMSA v1.0 RC15 — Local image provenance precheck

## Purpose

Improve supply-chain evidence hygiene before a future independent NMSA
security audit. Docker image identity and registry digest are **not**
cryptographic signature verification or supply-chain certification.

## Read-only precheck

`python -m nmsa.image_provenance --image-id sha256:<64 lowercase hex>`

The tool uses only a fixed, timeout-bounded Docker *image inspect*
command against the explicitly supplied immutable **local** image ID.
It asks Docker for the image ID, repository digest metadata, OS and
architecture. It never pulls, builds or runs an image, accepts a
mutable tag, copies Docker configuration environment variables,
prints raw registry names or returns host-specific secrets.

The result `LOCAL_IMAGE_IDENTIFIED` means only that the requested
local SHA256 image ID matches Linux image metadata. The
`registry_digest_present` signal says a repository digest was
advertised, not that it was authenticated or verified against a
trusted published provenance statement.

## Real check on Windows (2026-11-16)

Docker Desktop was temporarily started within the DeskMCP-owned command
session. The previously cached `node:20-bookworm-slim` image was
inspected by its full local SHA256 ID, with no image downloads.

Observed:
- Image identity matches: true
- Linux platform: true
- Registry digest count: 1
- Signature verified: false
- SBOM verified: false
- Vulnerability review completed: false
- Independent review completed: false
- Overall image provenance verified: false
- Repeated same-session Docker engine checks: 3/3 responded

This must **not** advance `image_provenance_review` from PENDING to
PASS in the RC14 release assurance gate.

## Remaining requirements

1. Define allowed image publisher and signed provenance/attestations,
   with independent trust-root policy and offline verification where feasible.
2. Verify an image's digest corresponds to reviewed content.
3. Review SBOM and vulnerability findings; resolve critical issues.
4. Verify Docker persists after the initiating DeskMCP launcher
   terminates, rather than only within its temporary process session.
5. Obtain independent security review and explicit owner release
   decision. No external skills or production execution authorized.

## Tests

- 142 Python unit tests passed locally with Semgrep installed.
- Seven new image-precheck tests cover identity mismatch, unsupported
  platforms, malformed metadata, invalid IDs, and redacted failures.
- Real Docker image inspection returned `LOCAL_IMAGE_IDENTIFIED`, but
  no certification was performed.

**RC15 CODE PRECHECK COMPLETE / RELEASE ASSURANCE REMAINS BLOCKED.**
