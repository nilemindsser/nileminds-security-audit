"""Conservative, privacy-preserving hourly correlation for Docker error indicators.

Uses only allowlisted local files and timestamp prefixes; no log lines,
exception details or identifying fields are ever returned or saved.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

from .docker_log_triage import (
    ALLOWED_FILES, ALLOWED_VM_FILES, SIGNALS, safe_log_file, running_on_windows,
)

# Timestamp may appear as a bracketed prefix or in JSON. Deliberately
# accept only a bounded leading prefix to avoid extracting arbitrary text.
STAMP = re.compile(
    r'^\s*(?:\[)?(?P<stamp>20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
    r'(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))'
)
JSON_STAMP = re.compile(
    r'^\s*\{.{0,160}?"(?:time|timestamp|ts)"\s*:\s*"(?P<stamp>20\d{2}-'
    r'\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))"'
)


def hour_bucket(line):
    if not isinstance(line, str):
        return None
    head = line[:240]
    matched = STAMP.match(head) or JSON_STAMP.match(head)
    if not matched:
        return None
    stamp = matched.group("stamp")
    try:
        # datetime accepts microsecond precision, so truncate only the
        # fractional nanosecond tail, not timezone information.
        stamp = re.sub(r'(\.\d{6})\d{1,3}(?=Z|[+-]\d{2}:\d{2}$)', r'\1', stamp)
        instant = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        return instant.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:00Z")
    except (ValueError, OverflowError):
        return None


def evaluate_lines(lines, source, buckets):
    parsed = 0
    matched = 0
    for line in lines:
        key = hour_bucket(line)
        if key is None:
            continue
        parsed += 1
        signs = [name for name, regex in SIGNALS.items() if regex.search(line)]
        if not signs:
            continue
        matched += 1
        record = buckets[key]
        record["sources"].add(source)
        for name in signs:
            record["signals"][name] += 1
    return parsed, matched


def timeline(root=None):
    if not running_on_windows():
        return {"status": "UNSUPPORTED_PLATFORM", "isolation_verified": False}
    base = Path(root) if root is not None else Path(os.environ.get("LOCALAPPDATA", "")) / "Docker" / "log"
    if not base.is_dir():
        return {"status": "INCOMPLETE", "reason": "docker_log_directory_unavailable",
                "isolation_verified": False, "root_cause_confirmed": False}
    buckets = defaultdict(lambda: {"sources": set(), "signals": defaultdict(int)})
    counted, excluded, parsed, signals = 0, 0, 0, 0
    for label, filename in {**ALLOWED_FILES, **ALLOWED_VM_FILES}.items():
        folder = base / ("vm" if label in ALLOWED_VM_FILES else "host")
        try:
            file = safe_log_file(folder / filename, folder)
            with file.open(encoding="utf-8", errors="replace") as handle:
                line_count, signal_count = evaluate_lines(handle, label, buckets)
        except (OSError, ValueError):
            excluded += 1
            continue
        counted += 1
        parsed += line_count
        signals += signal_count
    # Display only the latest 12 hours that actually contained indicators.
    out = []
    for hour in sorted(buckets)[-12:]:
        record = buckets[hour]
        out.append({"hour_utc": hour, "source_count": len(record["sources"]),
                    "signals": {name: min(record["signals"][name], 10000)
                                for name in sorted(SIGNALS) if record["signals"][name]}})
    return {
        "schema": "nmsa-docker-timeline-rc8",
        "status": "REVIEW" if out else "INCOMPLETE",
        "logs_processed": counted, "logs_excluded": excluded,
        "timestamped_lines": parsed, "signal_lines": signals,
        "hours_with_signals": len(buckets), "recent_hour_buckets": out,
        "root_cause_confirmed": False, "isolation_verified": False,
        "raw_logs_persisted": False,
        "limitations": "Hourly UTC co-occurrence only; no causal attribution, cross-clock guarantee or proof of Docker isolation",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only bounded Docker log UTC timeline")
    parser.parse_args(argv)
    report = timeline()
    print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "REVIEW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
