"""Read-only Windows Docker/WSL diagnostics for the NMSA sandbox gate.

Never starts/stops services, opens Docker Desktop, modifies WSL, or runs
containers. Returns normalized statuses only; no raw console logs.
"""
from __future__ import annotations

import argparse
import json
import platform
import subprocess

CHECKS = {
    "docker_context": ["docker", "context", "show"],
    "docker_server": ["docker", "info", "--format", "{{.OSType}}"],
    "docker_service": [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-Service -Name com.docker.service -ErrorAction SilentlyContinue).Status.ToString()",
    ],
    "wsl_engine": [
        "wsl.exe", "--list", "--quiet",
    ],
}
KNOWN_CONTEXTS = {"desktop-linux", "default"}
KNOWN_SERVICE_STATES = {"Running", "Stopped", "Paused", "StartPending", "StopPending"}


def safe_run(argv, *, timeout=8):
    """Return structured tool response and intentionally discard raw errors."""
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, errors="replace",
            encoding="utf-8", timeout=timeout, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "output": ""}
    return {"ok": result.returncode == 0, "output": result.stdout}


def diagnose(*, runner=safe_run):
    if platform.system() != "Windows":
        return {"status": "UNSUPPORTED_PLATFORM", "isolation_verified": False,
                "recommendation": "windows_only_diagnostics"}
    context = runner(CHECKS["docker_context"])
    engine = runner(CHECKS["docker_server"])
    service = runner(CHECKS["docker_service"])
    wsl = runner(CHECKS["wsl_engine"])
    context_value = context["output"].strip() if context["ok"] else ""
    service_value = service["output"].strip() if service["ok"] else ""
    linux_ready = engine["ok"] and engine["output"].strip() == "linux"
    signals = {
        "docker_context": context_value if context_value in KNOWN_CONTEXTS else "UNKNOWN",
        "linux_engine_available": linux_ready,
        "docker_service": service_value if service_value in KNOWN_SERVICE_STATES else "UNKNOWN",
        "wsl_query_available": wsl["ok"],
    }
    # Engine check is a single observation; never claim stable readiness.
    if not linux_ready:
        status = "BLOCKED"
        reason = "linux_docker_engine_unavailable"
    elif context_value != "desktop-linux":
        status = "REVIEW"
        reason = "unexpected_docker_context"
    else:
        status = "LIVENESS_ONLY"
        reason = "single_linux_engine_response"
    return {
        "status": status, "reason": reason, "signals": signals,
        "isolation_verified": False, "container_executed": False,
        "next_step": "run_nmsa_runtime_gate_then_review_local_image",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only Docker Desktop diagnostic")
    parser.add_argument("--output", help="Optional JSON output file")
    args = parser.parse_args(argv)
    report = diagnose()
    data = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        from pathlib import Path
        target = Path(args.output).resolve()
        if not target.parent.is_dir():
            parser.error("Output parent directory does not exist")
        target.write_text(data, encoding="utf-8")
    print(data.strip())
    return 2 if report["status"] in ("BLOCKED", "UNSUPPORTED_PLATFORM") else 1


if __name__ == "__main__":
    raise SystemExit(main())
