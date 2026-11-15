"""Bounded incident correlation: actionable review order, never auto-remediation.

Only normalized results of RC6 / RC8 are accepted. Raw logs, secrets and
arbitrary instructions are neither accepted nor copied into output.
"""
from __future__ import annotations
import argparse
import json
import re
from .docker_diagnostics import diagnose
from .docker_timeline import timeline
from .docker_log_triage import SIGNALS

STAMP = re.compile(r"20\d{2}-\d{2}-\d{2}T(?:0\d|1\d|2[0-3]):00Z\Z")
REQUIRED_DIAG = {"status", "signals"}
ALLOWED_STATES = {"BLOCKED", "REVIEW", "LIVENESS_ONLY", "INCOMPLETE", "UNSUPPORTED_PLATFORM"}


def analyze(diag, timed):
    if not isinstance(diag, dict) or not REQUIRED_DIAG.issubset(diag):
        raise ValueError("Invalid diagnostics")
    if diag["status"] not in ALLOWED_STATES or not isinstance(diag["signals"], dict):
        raise ValueError("Unknown diagnostic state")
    if not isinstance(timed, dict) or timed.get("status") not in {"REVIEW", "INCOMPLETE", "UNSUPPORTED_PLATFORM"}:
        raise ValueError("Invalid timeline")
    windows = timed.get("recent_hour_buckets", [])
    if not isinstance(windows, list) or len(windows) > 12:
        raise ValueError("Invalid hourly buckets")
    totals = {name: 0 for name in SIGNALS}
    distinct = 0
    for row in windows:
        if not isinstance(row, dict) or set(row) != {"hour_utc", "source_count", "signals"}:
            raise ValueError("Invalid hourly bucket")
        if not isinstance(row["hour_utc"], str) or not STAMP.fullmatch(row["hour_utc"]):
            raise ValueError("Invalid hour")
        if type(row["source_count"]) is not int or not 1 <= row["source_count"] <= 4:
            raise ValueError("Invalid source count")
        if not isinstance(row["signals"], dict) or not set(row["signals"]) <= set(SIGNALS):
            raise ValueError("Invalid signal names")
        for name, count in row["signals"].items():
            if type(count) is not int or not 0 < count <= 10000:
                raise ValueError("Invalid signal count")
            totals[name] += count
        if row["source_count"] > 1:
            distinct += 1
    engine_down = diag["status"] == "BLOCKED" or diag["signals"].get("linux_engine_available") is False
    if engine_down:
        state = "BLOCKED"
        next_action = "review_local_wsl_and_docker_error_context_read_only"
    elif diag["status"] != "LIVENESS_ONLY":
        state = "REVIEW"
        next_action = "validate_docker_context_and_linux_engine_read_only"
    else:
        state = "INCOMPLETE"
        next_action = "run_three_sample_engine_stability_gate"
    prioritized = sorted(
        ({"category": key, "observations": value} for key, value in totals.items() if value),
        key=lambda item: (-item["observations"], item["category"]),
    )
    return {
        "schema": "nmsa-incident-review-rc9",
        "status": state, "next_action": next_action,
        "signal_ranking": prioritized,
        "multi_source_hour_windows": distinct,
        "raw_content_included": False, "root_cause_confirmed": False,
        "isolation_verified": False, "remediation_authorized": False,
        "limitations": "Signal recurrence and hourly correlation do not establish a causal failure mechanism.",
    }


def review():
    return analyze(diagnose(), timeline())


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local read-only Docker incident review order")
    parser.parse_args(argv)
    result = review()
    print(json.dumps(result, sort_keys=True))
    return 2 if result["status"] == "BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
