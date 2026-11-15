"""Offline, non-executing signal triage: prioritize evidence without auto-clearing risks."""
from __future__ import annotations
import argparse
import json
from collections import Counter
from pathlib import Path

HIGH = {"instruction_override", "shell_pipeline", "credential_reference", "dynamic_execution"}
MEDIUM = {"network_command", "executable_file_requires_review", "symlink", "oversized_file"}
DOC_EXT = {".md", ".txt"}
TEST_DIRS = {"tests", "test", "evals", "fixtures", "examples", "docs"}
MAX_BYTES = 10_000_000


def classify(signal):
    path = signal["path"]
    parts = set(Path(path).parts)
    is_docs = Path(path).suffix.lower() in DOC_EXT
    is_fixture = bool(parts & TEST_DIRS)
    category = signal["category"]
    if category in HIGH:
        severity = "HIGH"
    elif category in MEDIUM:
        severity = "MEDIUM"
    else:
        severity = "UNKNOWN"
    context = "documentation" if is_docs else "test_or_example" if is_fixture else "source"
    # This ranking is priority only. A documentation example can contain prompt injection.
    priority = "P0" if severity == "HIGH" and context == "source" else "P1" if severity == "HIGH" else "P2"
    return {"path": path, "line": signal["line"], "category": category,
            "context": context, "priority": priority, "triage": "UNVERIFIED",
            "manual_review_required": True}


def triage_manifest(manifest):
    if manifest.get("schema") != "nmsa-skill-inventory-0.1":
        raise ValueError("Unrecognized inventory schema")
    entries = [classify(s) for s in manifest["signals"]]
    return {
        "schema": "nmsa-triage-0.5",
        "source_commit": manifest.get("source_commit"),
        "signal_count": len(entries),
        "priority_counts": dict(sorted(Counter(e["priority"] for e in entries).items())),
        "context_counts": dict(sorted(Counter(e["context"] for e in entries).items())),
        "category_counts": dict(sorted(Counter(e["category"] for e in entries).items())),
        "entries": entries,
        "verdict": "MANUAL_REVIEW_REQUIRED",
        "execution_authorized": False,
        "caveat": "Priorities are heuristics, not validated vulnerabilities or risk clearance."
    }


def main(argv=None):
    p = argparse.ArgumentParser(description="Prioritize offline skill-inventory signals")
    p.add_argument("inventory")
    p.add_argument("--output", required=True)
    args = p.parse_args(argv)
    inp, out = Path(args.inventory).resolve(), Path(args.output).resolve()
    if inp == out or not inp.is_file() or inp.stat().st_size > MAX_BYTES or not out.parent.is_dir():
        p.error("Require distinct input file and existing output parent")
    try:
        data = json.loads(inp.read_text(encoding="utf-8"))
        report = triage_manifest(data)
    except (ValueError, KeyError, TypeError) as exc:
        p.error("Invalid input inventory")
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"signals": report["signal_count"], "priorities": report["priority_counts"],
                      "verdict": report["verdict"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
