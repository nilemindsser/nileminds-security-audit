"""Explicitly restricted, opt-in Docker *fixture* runner.

Never launches external agent skills. Caller may run ONLY a fixed,
local benign fixture. Docker isolation is defense-in-depth, not a
guarantee against container escapes or a compromised container runtime.
"""
from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys

IMAGE = "python:3.12.9-alpine3.21"  # documentation only, never executed by mutable tag
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
FIXTURE = "print('NMSA_SANDBOX_FIXTURE_OK')"
MARKER = "NMSA_SANDBOX_FIXTURE_OK"


@dataclass(frozen=True)
class SandboxSpec:
    image: str = IMAGE
    memory: str = "128m"
    cpus: str = "0.5"
    pids_limit: int = 32


def docker_command(spec: SandboxSpec = SandboxSpec(), image_id: str | None = None):
    """Return a constant, locked-down test command, never a free-form script."""
    if spec != SandboxSpec():
        raise ValueError("Only the audited fixture profile is allowed")
    image_id = image_id or os.environ.get("NMSA_SANDBOX_IMAGE_ID", "")
    if not DIGEST_RE.fullmatch(image_id):
        raise ValueError("Explicit immutable local image ID sha256:<64 lowercase hex> required")
    return [
        "docker", "run", "--rm", "--pull", "never",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", str(spec.pids_limit),
        "--memory", spec.memory,
        "--cpus", spec.cpus,
        "--user", "65534:65534",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m,mode=1777",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--env", "PYTHONNOUSERSITE=1",
        "--workdir", "/tmp",
        image_id, "python", "-I", "-S", "-c", FIXTURE,
    ]


def readiness():
    if not shutil.which("docker"):
        return {"status": "BLOCKED", "reason": "docker_cli_missing"}
    try:
        result = subprocess.run(["docker", "info", "--format", "{{.OSType}}"],
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=12, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "BLOCKED", "reason": "docker_daemon_unavailable"}
    if result.returncode != 0 or result.stdout.strip() != "linux":
        return {"status": "BLOCKED", "reason": "linux_docker_daemon_required"}
    return {"status": "READY_FOR_FIXTURE", "reason": "docker_linux_daemon_detected"}


def run_fixture():
    state = readiness()
    if state["status"] != "READY_FOR_FIXTURE":
        return {"status": "BLOCKED", "reason": state["reason"]}
    image_id = os.environ.get("NMSA_SANDBOX_IMAGE_ID", "")
    if not DIGEST_RE.fullmatch(image_id):
        return {"status": "BLOCKED", "reason": "immutable_image_id_required"}
    try:
        # The caller explicitly selects an inspected immutable *local* image ID.
        # No automatic pull and never run against a mutable repo tag.
        inspect = subprocess.run(["docker", "image", "inspect", image_id,
                                  "--format", "{{.Id}}"],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=10, shell=False)
        if inspect.returncode != 0 or inspect.stdout.strip() != image_id:
            return {"status": "BLOCKED", "reason": "image_id_not_verified_locally"}
        result = subprocess.run(docker_command(image_id=image_id), capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=45, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "BLOCKED", "reason": "fixture_runtime_failure"}
    if result.returncode != 0 or result.stdout.strip() != MARKER:
        return {"status": "FAIL", "reason": "fixture_unexpected_output_or_exit"}
    return {"status": "FIXTURE_PASS", "reason": "benign_fixture_completed_not_isolation_proof"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Non-external-skills Docker fixture sandbox")
    parser.add_argument("--run-fixture", action="store_true", help="Execute fixed benign fixture if ready")
    args = parser.parse_args(argv)
    import json
    result = run_fixture() if args.run_fixture else readiness()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in ("READY_FOR_FIXTURE", "FIXTURE_PASS") else 2


if __name__ == "__main__":
    sys.exit(main())
