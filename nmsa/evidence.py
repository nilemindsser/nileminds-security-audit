"""Conservative finding evidence classifier; scanner signals are never proof.

This module doesn't access systems, fetch vulnerabilities or auto-approve findings.
"""
from __future__ import annotations
from collections import Counter

STATES = {"SCANNER_SIGNAL", "NEEDS_VALIDATION", "VALIDATED_IN_STAGING",
          "FALSE_POSITIVE", "ACCEPTED_RISK"}
REQUIRED_FOR_VALIDATED = {"reviewer", "target_revision", "reproduction_reference",
                          "impact_reference", "environment"}


def classify(record):
    if not isinstance(record, dict):
        raise ValueError("Finding must be an object")
    status = record.get("status", "SCANNER_SIGNAL")
    if status not in STATES:
        raise ValueError("Unknown finding state")
    if status == "VALIDATED_IN_STAGING":
        if not all(isinstance(record.get(k), str) and record[k].strip() for k in REQUIRED_FOR_VALIDATED):
            return {"status": "NEEDS_VALIDATION", "reason": "missing_independent_validation_evidence"}
        if record["environment"] != "non-production":
            return {"status": "NEEDS_VALIDATION", "reason": "production_reproduction_disallowed"}
        if record.get("independently_verified") is not True:
            return {"status": "NEEDS_VALIDATION", "reason": "independent_verification_missing"}
    if status in {"FALSE_POSITIVE", "ACCEPTED_RISK"}:
        if not isinstance(record.get("reviewer"), str) or not record["reviewer"].strip():
            return {"status": "NEEDS_VALIDATION", "reason": "reviewer_required"}
        if not isinstance(record.get("decision_reference"), str) or not record["decision_reference"].strip():
            return {"status": "NEEDS_VALIDATION", "reason": "decision_reference_required"}
    return {"status": status, "reason": "documented_state_not_execution_permission"}


def summarize(records):
    if not isinstance(records, list):
        raise ValueError("Expected list")
    decisions = [classify(r) for r in records]
    counts = Counter(r["status"] for r in decisions)
    return {"total": len(decisions), "counts": dict(sorted(counts.items())),
            "confirmed": counts["VALIDATED_IN_STAGING"],
            "note": "Validation evidence is metadata; not cryptographically attested. Independent review remains necessary."}
