"""Explicit two-phase Docker liveness gate across distinct OS processes.

A marker is untrusted diagnostic data, not authentication or security
certification. The second phase cannot repair/start Docker or run images.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time
from .runtime_gate import verify

SCHEMA = "nmsa-cross-session-rc12"
MAX_MARKER_BYTES = 1024
MAX_AGE_SECONDS = 600


def capture(marker, *, probe=verify, clock=time.time, process_id=os.getpid):
    result = probe(samples=3, delay=1)
    state = {
        "schema": SCHEMA, "nonce": secrets.token_hex(16),
        "created_utc_epoch": int(clock()), "process_id": process_id(),
        "ready": result.get("status") == "STABLE_FOR_FIXTURE_PRECHECK",
    }
    path = Path(marker)
    if path.exists() or path.is_symlink():
        raise ValueError("Existing marker must not be overwritten")
    if not path.parent.is_dir():
        raise ValueError("Marker parent missing")
    # Exclusive creation avoids races; marker is untrusted and never a credential.
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(state, file, sort_keys=True)
            file.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return {"status": "CAPTURED" if state["ready"] else "BLOCKED",
            "phase": "capture", "ready": state["ready"],
            "isolation_verified": False, "cross_session_verified": False}


def confirm(marker, *, probe=verify, clock=time.time, process_id=os.getpid):
    path = Path(marker)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MARKER_BYTES:
        return {"status": "BLOCKED", "reason": "invalid_or_missing_marker",
                "cross_session_verified": False, "isolation_verified": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return {"status": "BLOCKED", "reason": "invalid_marker",
                "cross_session_verified": False, "isolation_verified": False}
    expected = {"schema", "nonce", "created_utc_epoch", "process_id", "ready"}
    if (not isinstance(data, dict) or set(data) != expected
            or data["schema"] != SCHEMA
            or not isinstance(data["nonce"], str) or len(data["nonce"]) != 32
            or any(c not in "0123456789abcdef" for c in data["nonce"])
            or type(data["created_utc_epoch"]) is not int
            or type(data["process_id"]) is not int
            or type(data["ready"]) is not bool):
        return {"status": "BLOCKED", "reason": "invalid_marker_schema",
                "cross_session_verified": False, "isolation_verified": False}
    age = clock() - data["created_utc_epoch"]
    if age < 0 or age > MAX_AGE_SECONDS:
        reason = "stale_or_future_marker"
    elif data["process_id"] == process_id():
        reason = "same_process_not_independent"
    elif not data["ready"]:
        reason = "capture_phase_not_ready"
    else:
        reason = None
    if reason:
        return {"status": "BLOCKED", "reason": reason,
                "cross_session_verified": False, "isolation_verified": False}
    current = probe(samples=3, delay=1)
    ok = current.get("status") == "STABLE_FOR_FIXTURE_PRECHECK"
    return {
        "status": "CROSS_PROCESS_LIVENESS_PASS" if ok else "BLOCKED",
        "reason": "two_process_readiness_observed" if ok else "daemon_unavailable_after_session_boundary",
        "cross_session_verified": ok, "isolation_verified": False,
        "note": "Diagnostic marker is user-editable and not cryptographic proof; no independent container isolation was established",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Two-phase Docker liveness check across processes")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--capture", metavar="MARKER")
    group.add_argument("--confirm", metavar="MARKER")
    args = parser.parse_args(argv)
    try:
        result = capture(args.capture) if args.capture else confirm(args.confirm)
    except (OSError, ValueError):
        result = {"status": "BLOCKED", "reason": "marker_write_failed",
                  "cross_session_verified": False, "isolation_verified": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in ("CAPTURED", "CROSS_PROCESS_LIVENESS_PASS") else 2


if __name__ == "__main__":
    sys.exit(main())
