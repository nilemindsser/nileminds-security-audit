"""Fail-closed NMSA release assurance review. No production authorization.

The report summarizes declared evidence states. Supplied records remain
untrusted and cannot independently grant deployment or execution rights.
"""
from __future__ import annotations

import argparse
import json

FIELDS = (
    "code_ci",
    "synthetic_rule_benchmark",
    "real_container_behavior",
    "launcher_exit_persistence",
    "image_provenance_review",
    "image_vulnerability_triage",
    "independent_security_review",
    "owner_release_decision",
)
STATES = frozenset({"PASS", "FAIL", "NOT_RUN", "PENDING", "UNKNOWN"})
# A snapshot of the explicitly observed latest status, NOT a live CI query.
RC13_EVIDENCE_SNAPSHOT = {
    "code_ci": "PASS",
    "synthetic_rule_benchmark": "PASS",
    "real_container_behavior": "PASS",
    "launcher_exit_persistence": "FAIL",
    "image_provenance_review": "PENDING",
    "image_vulnerability_triage": "PENDING",  # RC20: 7 critical / 72 high signals
    "independent_security_review": "NOT_RUN",
    "owner_release_decision": "PENDING",
}


def assess(evidence):
    if not isinstance(evidence, dict) or set(evidence) != set(FIELDS):
        raise ValueError("Expected exactly the defined release-evidence categories")
    if any(type(state) is not str or state not in STATES for state in evidence.values()):
        raise ValueError("Invalid evidence state")
    checks = [
        {"gate": name, "state": evidence[name],
         "satisfied": evidence[name] == "PASS"}
        for name in FIELDS
    ]
    blocked = [check["gate"] for check in checks if not check["satisfied"]]
    # All self-reported gates passing can trigger an independent review only,
    # never execution or deployment. The owner decision must be verified
    # out-of-band by the release manager before any actual authorization.
    state = "BLOCKED" if blocked else "REVIEW_REQUIRED"
    return {
        "schema": "nmsa-release-assurance-rc22",
        "status": state,
        "checks": checks,
        "blocking_gates": blocked,
        "evidence_snapshot": "HISTORICAL_NOT_LIVE",
        "source_ci_freshness_verified": False,
        "independent_review_required": True,
        "security_certified": False,
        "production_authorized": False,
        "external_skill_execution_authorized": False,
        "note": "Historical self-declared evidence is neither live CI validation nor cryptographic attestation; owner approval and independent security validation are separate decisions",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review declared NMSA release evidence; no authorization")
    parser.parse_args(argv)
    report = assess(RC13_EVIDENCE_SNAPSHOT)
    print(json.dumps(report, sort_keys=True))
    return 2 if report["status"] == "BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
