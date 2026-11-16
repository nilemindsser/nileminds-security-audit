"""Read-only, bounded, fail-closed local Docker image provenance signals.

A matching local image ID or registry digest is NOT a verified signature,
trust decision, SBOM, or independent supply-chain review.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess

from .sandbox import DIGEST_RE

TEMPLATE = "{{.Id}}|{{json .RepoDigests}}|{{.Os}}|{{.Architecture}}"
REGISTRY_DIGEST = re.compile(r"^[^\s@|]{1,256}@sha256:[0-9a-f]{64}$")
MAX_RESPONSE = 8192


def interpret(stdout, expected_id):
    if not isinstance(stdout, str) or len(stdout) > MAX_RESPONSE:
        return {"status": "BLOCKED", "reason": "invalid_or_oversized_image_metadata",
                "image_provenance_verified": False, "isolation_verified": False}
    chunks = stdout.strip().split("|")
    if len(chunks) != 4:
        return {"status": "BLOCKED", "reason": "invalid_image_metadata",
                "image_provenance_verified": False, "isolation_verified": False}
    local_id, raw_digests, os_name, architecture = chunks
    if local_id != expected_id or os_name != "linux" or architecture not in {"amd64", "arm64"}:
        return {"status": "BLOCKED", "reason": "image_identity_or_platform_mismatch",
                "image_provenance_verified": False, "isolation_verified": False}
    try:
        digests = json.loads(raw_digests)
    except (TypeError, ValueError):
        digests = None
    if digests is not None and (not isinstance(digests, list)
        or len(digests) > 40 or any(not isinstance(x, str) or not REGISTRY_DIGEST.fullmatch(x) for x in digests)):
        return {"status": "BLOCKED", "reason": "malformed_registry_digests",
                "image_provenance_verified": False, "isolation_verified": False}
    return {
        "status": "LOCAL_IMAGE_IDENTIFIED",
        "local_image_id_matches": True,
        "linux_platform": True,
        "registry_digest_present": bool(digests),
        "registry_digest_count": len(digests or []),
        "image_provenance_verified": False,
        "signature_verified": False,
        "sbom_verified": False,
        "vulnerability_review_completed": False,
        "independent_review_completed": False,
        "isolation_verified": False,
        "note": "Digest metadata is a locator, not a verified signature or trusted origin.",
    }


def inspect(image_id, *, runner=subprocess.run):
    if not isinstance(image_id, str) or not DIGEST_RE.fullmatch(image_id):
        return {"status": "BLOCKED", "reason": "immutable_sha256_image_id_required",
                "image_provenance_verified": False, "isolation_verified": False}
    try:
        result = runner(
            ["docker", "image", "inspect", image_id, "--format", TEMPLATE],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "BLOCKED", "reason": "docker_inspect_unavailable",
                "image_provenance_verified": False, "isolation_verified": False}
    if result.returncode != 0:
        return {"status": "BLOCKED", "reason": "local_image_unavailable",
                "image_provenance_verified": False, "isolation_verified": False}
    return interpret(result.stdout, image_id)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only, redacted local Docker image identity signals")
    parser.add_argument("--image-id", default=os.environ.get("NMSA_SANDBOX_IMAGE_ID", ""))
    args = parser.parse_args(argv)
    result = inspect(args.image_id)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "LOCAL_IMAGE_IDENTIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
