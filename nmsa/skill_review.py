"""Read-only manifest and heuristic review for third-party agent skills.

No external skill is executed, imported, installed, or activated here.
Heuristic matches are signals for manual investigation, not proof of malice.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

TEXT_EXT = {".md", ".json", ".yaml", ".yml", ".py", ".js", ".cjs", ".mjs", ".ts",
            ".sh", ".ps1", ".toml", ".xml", ".txt"}
MAX_FILE_BYTES = 2_000_000
PATTERNS = {
    "shell_pipeline": re.compile(r"(?:curl|wget)\s+[^\n]{0,200}\|\s*(?:sh|bash)\b", re.I),
    "dynamic_execution": re.compile(r"\b(?:eval|exec|Invoke-Expression)\s*\(", re.I),
    "credential_reference": re.compile(r"(?:\.ssh[/\\]|\.aws[/\\]|\.env\b|id_rsa|github_pat_|ghp_)", re.I),
    "instruction_override": re.compile(r"(?:ignore\s+(?:all\s+)?previous\s+instructions|disable\s+(?:security|safety)\s+checks)", re.I),
    "network_command": re.compile(r"\b(?:curl|wget|Invoke-WebRequest)\b", re.I),
}
EXECUTABLE_EXT = {".py", ".sh", ".ps1", ".js", ".cjs", ".mjs", ".exe", ".bat", ".cmd"}


def git_revision(root: Path) -> str | None:
    try:
        p = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=10,
                           shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    candidate = p.stdout.strip()
    return candidate if p.returncode == 0 and re.fullmatch("[0-9a-f]{40}", candidate) else None


def inventory(root: Path) -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Source must be a directory")
    rows, issues = [], []
    total = 0
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts:
            continue
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            issues.append({"path": rel, "category": "symlink", "line": 0})
            continue
        if not path.is_file():
            continue
        total += 1
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            issues.append({"path": rel, "category": "oversized_file", "line": 0})
            rows.append({"path": rel, "size": size, "sha256": None, "type": "oversized"})
            continue
        raw = path.read_bytes()
        rows.append({"path": rel, "size": size, "sha256": hashlib.sha256(raw).hexdigest(),
                     "type": "executable" if path.suffix.lower() in EXECUTABLE_EXT else "data"})
        if path.suffix.lower() in EXECUTABLE_EXT:
            issues.append({"path": rel, "category": "executable_file_requires_review", "line": 0})
        if path.suffix.lower() in TEXT_EXT:
            decoded = raw.decode("utf-8", errors="replace")
            for line_no, line in enumerate(decoded.splitlines(), 1):
                # Never store matched excerpts, secret values, or the line itself.
                for name, pattern in PATTERNS.items():
                    if pattern.search(line):
                        issues.append({"path": rel, "category": name, "line": line_no})
    manifest = {"schema": "nmsa-skill-inventory-0.1", "source_commit": git_revision(root),
                "file_count": total, "files": rows, "signals": issues,
                "execution_authorized": False, "execution_supported": False,
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "note": "Heuristics only. Never run source scripts automatically."}
    return manifest


def main(argv=None):
    p = argparse.ArgumentParser(description="Inventory untrusted skills without execution")
    p.add_argument("source", help="Existing locally cloned source directory")
    p.add_argument("--output", required=True, help="Output JSON file OUTSIDE the source directory")
    args = p.parse_args(argv)
    src, output = Path(args.source).resolve(), Path(args.output).resolve()
    if not src.is_dir() or not output.parent.is_dir():
        p.error("Source directory and output parent must exist")
    if src == output or src in output.parents:
        p.error("Output must not be inside source tree")
    data = inventory(src)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Inventory: {data['file_count']} files, {len(data['signals'])} review signals; execution disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
