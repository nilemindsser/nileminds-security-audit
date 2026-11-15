"""Local, read-only, redacted Docker diagnostic log triage.

No log lines, raw exception messages, paths, environment variables, IP
addresses or tokens leave this module. Match counts are indicators only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import os
import re

MAX_LOG_BYTES = 2_000_000
SIGNALS = {
    "wsl_failure": re.compile(r"\b(?:wsl|lxss|distribution)\b.{0,140}\b(?:fail(?:ed|ure)?|error|unavailable)\b|\b(?:fail(?:ed|ure)?|error)\b.{0,140}\b(?:wsl|lxss)\b", re.I),
    "daemon_pipe": re.compile(r"(?:dockerDesktopLinuxEngine|docker_engine|named pipe|npipe).{0,140}(?:not found|unavailable|failed|error)|(?:failed|error).{0,140}(?:dockerDesktopLinuxEngine|named pipe|npipe)", re.I),
    "backend_exit": re.compile(r"(?:backend|engine|daemon).{0,100}(?:crash(?:ed)?|exit(?:ed)?|shutdown|terminated|panic)", re.I),
    "resource_failure": re.compile(r"(?:out of memory|oom[- ]kill|no space left|disk full)", re.I),
    "permission_failure": re.compile(r"(?:permission denied|access is denied|access denied)", re.I),
}
ALLOWED_FILES = {
    "desktop": "docker-desktop.exe.log",
    "backend": "com.docker.backend.exe.log",
    "monitor": "monitor.log",
}
ALLOWED_VM_FILES = {"vm_init": "init.log"}


def assess_log(content):
    if not isinstance(content, str):
        raise ValueError("Expected sanitized input text type")
    return {name: min(len(pattern.findall(content)), 10000)
            for name, pattern in SIGNALS.items()}


def safe_log_file(path, root):
    root = Path(root).resolve(strict=True)
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise ValueError("Not an ordinary file")
    resolved = file.resolve(strict=True)
    if resolved.parent != root or file.stat().st_size > MAX_LOG_BYTES:
        raise ValueError("Log outside allowed directory or too large")
    return resolved


def triage(root=None):
    if os.name != "nt":
        return {"status": "UNSUPPORTED_PLATFORM", "logs_processed": 0,
                "isolation_verified": False}
    base = Path(root) if root is not None else Path(os.environ.get("LOCALAPPDATA", "")) / "Docker" / "log"
    if not base.is_dir():
        return {"status": "INCOMPLETE", "reason": "docker_log_directory_unavailable",
                "logs_processed": 0, "isolation_verified": False}
    totals = {name: 0 for name in SIGNALS}
    counted = 0
    excluded = 0
    for label, basename in {**ALLOWED_FILES, **ALLOWED_VM_FILES}.items():
        subdir = "vm" if label in ALLOWED_VM_FILES else "host"
        folder = base / subdir
        file = folder / basename
        try:
            resolved = safe_log_file(file, folder)
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError, UnicodeError):
            excluded += 1
            continue
        signals = assess_log(text)
        for name, count in signals.items():
            totals[name] += count
        counted += 1
    return {
        "schema": "nmsa-docker-log-triage-rc7",
        "status": "REVIEW" if counted else "INCOMPLETE",
        "logs_processed": counted,
        "logs_excluded": excluded,
        "signal_counts": totals,
        "raw_logs_persisted": False,
        "isolation_verified": False,
        "root_cause_confirmed": False,
        "note": "Keyword-level indicators only; independent error-context review required",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only, privacy-safe local Docker log signals")
    args = parser.parse_args(argv)
    report = triage()
    print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "REVIEW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
