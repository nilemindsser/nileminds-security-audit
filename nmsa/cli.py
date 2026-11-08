"""Local, read-only orchestration of installed security scanners.

No auto-download, shell commands, or AI invocation. Optional binaries are required.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from .reports import sarif, html

TOOLS = {"semgrep": True, "gitleaks": True, "trivy": True}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build"}
SEVERITY = {"CRITICAL": 4, "HIGH": 3, "ERROR": 3, "MEDIUM": 2, "WARNING": 2, "LOW": 1, "INFO": 0}


def run(tool, target, timeout):
    exe = shutil.which(tool)
    if not exe:
        configured = os.environ.get("NMSA_" + tool.upper() + "_BIN")
        if configured and Path(configured).is_file():
            exe = str(Path(configured).resolve())
    if not exe:
        return {"tool": tool, "status": "NOT_INSTALLED", "findings": [], "message": "Install manually from the official project"}
    with tempfile.TemporaryDirectory(prefix="nmsa-") as tmp:
        result_path = Path(tmp) / "gitleaks.json"
        if tool == "semgrep":
            cmd = [exe, "scan", "--config", str(Path(__file__).with_name("rules.yml")), "--json", "--metrics", "off", "--disable-version-check", str(target)]
        elif tool == "gitleaks":
            cmd = [exe, "dir", str(target), "--report-format", "json", "--report-path", str(result_path), "--no-banner"]
        else:
            cmd = [exe, "fs", "--format", "json", "--scanners", "vuln,misconfig,secret", "--no-progress", "--skip-db-update", "--skip-java-db-update", str(target)]
        env = dict(os.environ)
        env["DO_NOT_TRACK"] = "1"
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, encoding="utf-8", errors="replace", timeout=timeout, cwd=tmp, env=env, shell=False)
        except subprocess.TimeoutExpired:
            return {"tool": tool, "status": "TIMEOUT", "findings": [], "message": "Scanner exceeded timeout"}
        except OSError as e:
            return {"tool": tool, "status": "ERROR", "findings": [], "message": type(e).__name__}
        raw = result_path.read_text(encoding="utf-8") if tool == "gitleaks" and result_path.exists() else proc.stdout
        try:
            data = json.loads(raw) if raw.strip() else ([] if tool == "gitleaks" else {})
        except (ValueError, UnicodeError):
            return {"tool": tool, "status": "ERROR", "findings": [], "message": "Invalid scanner JSON; stderr suppressed to avoid leaking secrets"}
        if tool == "semgrep" and isinstance(data, dict) and data.get("errors"):
            return {"tool": tool, "status": "ERROR", "findings": [], "message": "Semgrep reported parse or configuration errors"}
        items = parse(tool, data, target)
        # Gitleaks 1 = secrets found; Semgrep 1 = findings; Trivy 0 normally.
        accepted = (0, 1) if tool in ("gitleaks", "semgrep") else (0,)
        status = "COMPLETE" if proc.returncode in accepted else "ERROR"
        return {"tool": tool, "status": status, "findings": items if status == "COMPLETE" else [], "exit_code": proc.returncode,
                "message": "" if status == "COMPLETE" else "Scanner exit nonzero; stderr suppressed"}


def safe_path(path, root):
    # Avoid writing arbitrary absolute path or content to report.
    if not path:
        return ""
    try:
        p = Path(path)
        if not p.is_absolute():
            p = root / p
        return str(p.resolve().relative_to(root.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        return "[outside-target]"


def add(items, tool, rule, severity, path, line, root):
    rule = re.sub(r"[^a-zA-Z0-9_.:/-]", "_", str(rule))[:150]
    try:
        line = max(0, int(line or 0))
    except (TypeError, ValueError):
        line = 0
    items.append({"tool": tool, "rule": rule, "severity": str(severity).upper(),
                  "path": safe_path(path, root), "line": line})


def parse(tool, data, root):
    results = []
    if tool == "semgrep" and isinstance(data, dict):
        for v in data.get("results", []):
            if not isinstance(v, dict):
                continue
            rule_id = str(v.get("check_id", "unknown"))
            if "nmsa.python." in rule_id:
                rule_id = rule_id[rule_id.find("nmsa.python."):]
            add(results, tool, rule_id, v.get("extra", {}).get("severity", "INFO"),
                v.get("path"), v.get("start", {}).get("line"), root)
    elif tool == "gitleaks" and isinstance(data, list):
        for v in data:
            if isinstance(v, dict):
                add(results, tool, v.get("RuleID", "secret"), "HIGH", v.get("File"), v.get("StartLine"), root)
    elif tool == "trivy" and isinstance(data, dict):
        for section in data.get("Results", []):
            if not isinstance(section, dict):
                continue
            path = section.get("Target")
            for category in ("Vulnerabilities", "Misconfigurations", "Secrets"):
                for v in section.get(category) or []:
                    if not isinstance(v, dict):
                        continue
                    rule = v.get("VulnerabilityID") or v.get("ID") or v.get("RuleID") or "secret"
                    sev = v.get("Severity") or ("HIGH" if category == "Secrets" else "INFO")
                    add(results, tool, rule, sev, path, v.get("StartLine") or v.get("Line"), root)
    return results


def deduplicate(results):
    # Preserve cross-engine provenance for the same location/rule.
    index = {}
    for r in results:
        key = (r["path"], r["line"], r["rule"])
        if key not in index:
            index[key] = {k: v for k, v in r.items() if k != "tool"}
            index[key]["tools"] = [r["tool"]]
        elif r["tool"] not in index[key]["tools"]:
            index[key]["tools"].append(r["tool"])
    return sorted(index.values(), key=lambda x: (-SEVERITY.get(x["severity"], 0), x["path"], x["line"], x["rule"]))


def markdown(report):
    lines = ["# Nile Minds Security Audit", "", f"Status: **{report['status']}**", "",
             "## Scanner status", "", "| Scanner | Status | Findings |", "|---|---|---:|"]
    for tool in report["scanners"]:
        lines.append(f"| {tool['tool']} | {tool['status']} | {len(tool['findings'])} |")
    lines += ["", "## Findings", "", "| Severity | Rule | Location | Tools |", "|---|---|---|---|"]
    for f in report["findings"]:
        lines.append(f"| {f['severity']} | {f['rule']} | {f['path']}:{f['line']} | {', '.join(f['tools'])} |")
    lines += ["", "Incomplete scanners do not imply a clean scan. Findings are unverified until independently triaged.",
              "Raw scanner messages, secret values, and source snippets are not included."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nile Minds local security audit (read-only)")
    parser.add_argument("target", help="Existing local project directory")
    parser.add_argument("--output", required=True, help="Existing output directory outside project")
    parser.add_argument("--tools", nargs="+", choices=sorted(TOOLS), default=list(TOOLS))
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    target, output = Path(args.target).expanduser().resolve(), Path(args.output).expanduser().resolve()
    if not target.is_dir() or not output.is_dir():
        parser.error("Target and output must be existing directories")
    if target == output or target in output.parents or output in target.parents:
        parser.error("Output must be outside target, with no ancestor relationship")
    if not 1 <= args.timeout <= 3600:
        parser.error("Timeout must be between 1 and 3600 seconds")
    scanners = [run(tool, target, args.timeout) for tool in dict.fromkeys(args.tools)]
    findings = deduplicate([f for tool in scanners for f in tool["findings"]])
    complete = all(t["status"] == "COMPLETE" for t in scanners)
    high = any(SEVERITY.get(f["severity"], 0) >= 3 for f in findings)
    status = "INCOMPLETE" if not complete else ("FAIL" if high else "REVIEW" if findings else "PASS")
    report = {"schema_version": "0.1", "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "status": status, "scanners": scanners, "findings": findings,
              "note": "PASS means enabled scanners returned no findings, not a security guarantee."}
    (output / "security-audit.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (output / "SECURITY-AUDIT.md").write_text(markdown(report), encoding="utf-8")
    (output / "security-audit.sarif").write_text(json.dumps(sarif(report), indent=2), encoding="utf-8")
    (output / "security-audit.html").write_text(html(report), encoding="utf-8")
    print(f"Audit: {status}; findings: {len(findings)}; outputs: {output}")
    return 0 if status == "PASS" else 2 if status == "INCOMPLETE" else 1


if __name__ == "__main__":
    sys.exit(main())
