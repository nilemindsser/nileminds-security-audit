"""Fail-closed Docker runtime stability gate; no containers or images launched.

Distinct readiness samples detect an engine that starts and immediately exits.
This is only liveness evidence, NOT sandbox isolation certification.
"""
from __future__ import annotations
import argparse
import json
import shutil
import subprocess
import time


def sample():
    if not shutil.which("docker"):
        return {"ok": False, "reason": "docker_cli_missing"}
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}} {{.ServerVersion}}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "reason": "daemon_unavailable"}
    parts = result.stdout.strip().split()
    if result.returncode != 0 or len(parts) != 2 or parts[0] != "linux":
        return {"ok": False, "reason": "linux_daemon_required"}
    # Never echo untrusted daemon errors or machine-specific engine metadata.
    return {"ok": True, "reason": "linux_daemon_responded"}


def verify(samples=3, delay=2, sleeper=time.sleep):
    if not isinstance(samples, int) or not 2 <= samples <= 5:
        raise ValueError("2-5 readiness samples required")
    if not isinstance(delay, (int, float)) or not 0 <= delay <= 10:
        raise ValueError("delay out of bounds")
    results = []
    for index in range(samples):
        if index:
            sleeper(delay)
        results.append(sample())
        if not results[-1]["ok"]:
            return {"status": "BLOCKED", "reason": "unstable_or_unavailable_daemon",
                    "passed_samples": sum(int(r["ok"]) for r in results),
                    "required_samples": samples, "isolation_verified": False}
    return {"status": "STABLE_FOR_FIXTURE_PRECHECK", "reason": "multiple_linux_daemon_responses",
            "passed_samples": samples, "required_samples": samples,
            "isolation_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check repeated Docker Linux engine readiness")
    parser.add_argument("--samples", type=int, choices=[2, 3, 4, 5], default=3)
    parser.add_argument("--delay", type=float, default=2)
    args = parser.parse_args(argv)
    try:
        result = verify(samples=args.samples, delay=args.delay)
    except ValueError:
        parser.error("Invalid interval")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "STABLE_FOR_FIXTURE_PRECHECK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
