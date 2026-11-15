"""Read-only differentiation of WSL Linux health and Docker Engine health.

Fixed commands. Never resets WSL, starts a container, obtains secrets,
changes services, or returns raw stderr/stdout.
"""
from __future__ import annotations
import argparse
import json
import platform
import subprocess

COMMANDS = {
    "wsl_ubuntu": ["wsl.exe", "-d", "Ubuntu", "--exec", "/bin/uname", "-s"],
    "wsl_docker": ["wsl.exe", "-d", "docker-desktop", "--exec", "/bin/uname", "-s"],
    "docker_engine": ["docker", "info", "--format", "{{.OSType}}"],
}
def check(argv, timeout=10):
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "Linux" if argv[0] == "wsl.exe" else (
        result.returncode == 0 and result.stdout.strip() == "linux"
    )


def differential(*, checker=check, system=platform.system):
    if system() != "Windows":
        return {"status": "UNSUPPORTED_PLATFORM", "isolation_verified": False}
    observations = {name: bool(checker(argv)) for name, argv in COMMANDS.items()}
    if observations["docker_engine"]:
        state, next_action = "LIVENESS_ONLY", "run_repeated_stability_gate"
    elif observations["wsl_docker"] and observations["wsl_ubuntu"]:
        state, next_action = "DOCKER_BACKEND_REVIEW", "inspect_docker_desktop_backend_without_reset"
    elif observations["wsl_docker"]:
        state, next_action = "DOCKER_BACKEND_REVIEW", "inspect_docker_desktop_backend_without_reset"
    else:
        state, next_action = "WSL_OR_DOCKER_DISTRO_REVIEW", "inspect_wsl_error_context_read_only"
    return {
        "schema": "nmsa-wsl-engine-differential-rc10",
        "status": state, "observations": observations,
        "next_action": next_action,
        "root_cause_confirmed": False, "isolation_verified": False,
        "container_executed": False, "remediation_authorized": False,
        "limitations": "Read-only fixed Linux commands may briefly start a WSL distro; successful WSL command is not proof of stable Docker backend.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only WSL vs Docker backend health check")
    parser.parse_args(argv)
    result = differential()
    print(json.dumps(result, sort_keys=True))
    return 1 if result.get("status") in ("LIVENESS_ONLY", "DOCKER_BACKEND_REVIEW") else 2


if __name__ == "__main__":
    raise SystemExit(main())
