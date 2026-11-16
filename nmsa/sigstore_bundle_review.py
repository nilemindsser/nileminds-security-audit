"""Offline Sigstore bundle verifier: non-authorizing, fail-closed.

No keyless signer identity is ever derived from an untrusted bundle.
No network or installer; no arbitrary commands. This verifies a local
signed blob, NOT the local Docker image runtime or a registry image.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

MAX_ARTIFACT = 64_000_000
MAX_BUNDLE = 1_000_000
MAX_ROOT = 1_000_000
IDENTITY = re.compile(r"^[^\s\x00-\x1f]{5,512}$")
ISSUER = re.compile(r"^https://[^\s\x00-\x1f]{4,512}$")


def local_file(value, max_bytes):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("invalid_file")
    path = Path(value)
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing_or_symlink")
    resolved = path.resolve(strict=True)
    if path.stat().st_size <= 0 or path.stat().st_size > max_bytes:
        raise ValueError("file_size_invalid")
    return str(resolved)


def verify_blob(blob, bundle, trusted_root, identity, issuer, *, runner=subprocess.run):
    blocked = {"status": "BLOCKED", "signature_verified": False,
               "image_provenance_verified": False, "production_authorized": False}
    if (not isinstance(identity, str) or not IDENTITY.fullmatch(identity)
        or not isinstance(issuer, str) or not ISSUER.fullmatch(issuer)):
        return {**blocked, "reason": "trusted_signer_identity_and_oidc_issuer_required"}
    try:
        paths = (local_file(blob, MAX_ARTIFACT),
                 local_file(bundle, MAX_BUNDLE),
                 local_file(trusted_root, MAX_ROOT))
    except (ValueError, OSError):
        return {**blocked, "reason": "missing_invalid_or_oversized_local_evidence"}
    # Only the expected signer identity and issuer supplied by external policy
    # are accepted, not values echoed from the bundle itself.
    command = [
        "cosign", "verify-blob", paths[0], "--bundle", paths[1],
        "--trusted-root", paths[2], "--offline",
        "--certificate-identity", identity,
        "--certificate-oidc-issuer", issuer,
    ]
    try:
        result = runner(command, capture_output=True, text=True,
                        encoding="utf-8", errors="replace",
                        timeout=40, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return {**blocked, "reason": "cosign_unavailable_or_timed_out"}
    if result.returncode:
        return {**blocked, "reason": "bundle_verification_failed"}
    return {
        "status": "SIGNED_BLOB_VERIFIED",
        "signature_verified": True,
        "image_provenance_verified": False,
        "production_authorized": False,
        "trusted_root_reviewed": False,
        "publisher_authorized": False,
        "note": "Sigstore local blob verification is not publisher trust approval, Docker image verification, SBOM audit, or container security certification.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline local blob signature review (no automatic release authorization)")
    parser.add_argument("--blob", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--trusted-root", required=True)
    parser.add_argument("--certificate-identity", required=True)
    parser.add_argument("--certificate-oidc-issuer", required=True)
    args = parser.parse_args(argv)
    result = verify_blob(args.blob, args.bundle, args.trusted_root,
                         args.certificate_identity, args.certificate_oidc_issuer)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "SIGNED_BLOB_VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
