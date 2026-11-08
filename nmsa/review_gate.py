"""Offline human review register with hash pinning; never grants execution.

Review files are untrusted and NOT cryptographic authorizations. They provide
an auditable checklist only, and the runtime never imports external skills.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from .skill_review import inventory

ALLOWED = {"UNREVIEWED", "BENIGN_EXAMPLE", "REQUIRES_MITIGATION", "CONFIRMED_RISK"}
PERMISSIONS = {"none", "read_project", "network", "write_project", "secrets", "execute_commands"}
MAX_REVIEW_BYTES = 3_000_000


def fingerprint(manifest: dict) -> str:
    data = {"source_commit": manifest["source_commit"],
            "files": manifest["files"], "signals": manifest["signals"]}
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def review_template(manifest: dict) -> dict:
    entries = [{"id": n, "path": row["path"], "line": row["line"], "category": row["category"],
                "decision": "UNREVIEWED", "reason": ""}
               for n, row in enumerate(manifest["signals"])]
    return {"schema": "nmsa-manual-review-0.4", "source_commit": manifest["source_commit"],
            "inventory_sha256": fingerprint(manifest), "requested_permissions": ["none"],
            "reviewer": "", "owner_approval_reference": "",
            "entries": entries, "review_verdict": "NOT_REVIEWED",
            "execution_authorized": False}


def validate_review(manifest: dict, review: dict) -> dict:
    reasons = []
    if review.get("schema") != "nmsa-manual-review-0.4":
        reasons.append("invalid_schema")
    if not manifest.get("source_commit"):
        reasons.append("missing_source_commit")
    if review.get("source_commit") != manifest["source_commit"]:
        reasons.append("source_commit_mismatch")
    if review.get("inventory_sha256") != fingerprint(manifest):
        reasons.append("inventory_fingerprint_mismatch")
    if review.get("execution_authorized") is not False:
        reasons.append("execution_flag_must_be_false")
    permissions = review.get("requested_permissions")
    if not isinstance(permissions, list) or not permissions or any(p not in PERMISSIONS for p in permissions):
        reasons.append("unknown_permission")
    entries = review.get("entries")
    original = manifest["signals"]
    if not isinstance(entries, list) or len(entries) != len(original):
        reasons.append("signal_set_mismatch")
    else:
        for i, (item, expected) in enumerate(zip(entries, original)):
            if not isinstance(item, dict) or any(item.get(k) != v for k, v in
                     [("id", i), ("path", expected["path"]), ("line", expected["line"]),
                      ("category", expected["category"])]):
                reasons.append("signal_identity_mismatch")
                break
            if item.get("decision") not in ALLOWED:
                reasons.append("unknown_decision")
                break
            reason = item.get("reason")
            if not isinstance(reason, str) or len(reason) > 1000:
                reasons.append("invalid_reason")
                break
            if item["decision"] != "UNREVIEWED" and not reason.strip():
                reasons.append("missing_review_reason")
                break
    if review.get("review_verdict") not in ("NOT_REVIEWED", "REVIEWED_WITH_RISKS", "REVIEWED_NO_CONFIRMED_RISK"):
        reasons.append("invalid_review_verdict")
    if not isinstance(review.get("reviewer"), str) or len(review.get("reviewer", "")) > 128:
        reasons.append("invalid_reviewer")
    if not isinstance(review.get("owner_approval_reference"), str) or len(review.get("owner_approval_reference", "")) > 256:
        reasons.append("invalid_owner_reference")
    if reasons:
        return {"status": "BLOCKED", "reasons": sorted(set(reasons)), "execution_authorized": False}
    decisions = [e["decision"] for e in entries]
    if (not review.get("reviewer", "").strip() or
        any(d in {"UNREVIEWED", "REQUIRES_MITIGATION", "CONFIRMED_RISK"} for d in decisions) or
        review.get("review_verdict") != "REVIEWED_NO_CONFIRMED_RISK"):
        return {"status": "MANUAL_REVIEW_REQUIRED", "reasons": ["outstanding_review_or_risks"],
                "execution_authorized": False}
    # Even a fully reviewed register does not authorize execution or constitute a sandbox.
    return {"status": "REVIEW_DOCUMENTED_NOT_AUTHORIZED",
            "reasons": ["independent_owner_approval_and_sandbox_required"],
            "execution_authorized": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline skill checklist; never activates skills")
    parser.add_argument("action", choices=["prepare", "verify"])
    parser.add_argument("source")
    parser.add_argument("--review", required=True, help="Review JSON path outside source")
    args = parser.parse_args(argv)
    source = Path(args.source).resolve()
    review_path = Path(args.review).resolve()
    if not source.is_dir() or source == review_path or source in review_path.parents:
        parser.error("Valid source and external review path required")
    current = inventory(source)
    if args.action == "prepare":
        if not review_path.parent.is_dir() or review_path.exists():
            parser.error("Review must be a new file in an existing external directory")
        review_path.write_text(json.dumps(review_template(current), indent=2) + "\n", encoding="utf-8")
        print("Review template created; execution DISABLED")
        return 0
    if not review_path.is_file() or review_path.stat().st_size > MAX_REVIEW_BYTES:
        parser.error("Valid bounded review file required")
    try:
        data = json.loads(review_path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError):
        parser.error("Review must be valid UTF-8 JSON")
    result = validate_review(current, data)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "REVIEW_DOCUMENTED_NOT_AUTHORIZED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
