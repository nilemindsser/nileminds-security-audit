"""RC22 prevents historical CI evidence or untriaged image risks being a release approval."""
import unittest
from nmsa.release_assurance import FIELDS, RC13_EVIDENCE_SNAPSHOT, assess


class ReleasePreflightRC22Tests(unittest.TestCase):
    def test_current_snapshot_explicitly_blocks_vulnerability_triage(self):
        report = assess(RC13_EVIDENCE_SNAPSHOT)
        self.assertEqual(report["status"], "BLOCKED")
        self.assertIn("image_vulnerability_triage", report["blocking_gates"])
        self.assertEqual(report["evidence_snapshot"], "HISTORICAL_NOT_LIVE")
        self.assertFalse(report["source_ci_freshness_verified"])
        self.assertFalse(report["production_authorized"])

    def test_missing_vulnerability_triage_field_rejected(self):
        payload = dict(RC13_EVIDENCE_SNAPSHOT)
        del payload["image_vulnerability_triage"]
        with self.assertRaises(ValueError):
            assess(payload)

    def test_only_vulnerability_triage_pending_prevents_release(self):
        payload = {field: "PASS" for field in FIELDS}
        payload["image_vulnerability_triage"] = "PENDING"
        report = assess(payload)
        self.assertEqual(report["blocking_gates"], ["image_vulnerability_triage"])
        self.assertFalse(report["security_certified"])

    def test_all_self_reported_pass_still_cannot_authorize_release(self):
        report = assess({field: "PASS" for field in FIELDS})
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertFalse(report["source_ci_freshness_verified"])
        self.assertFalse(report["production_authorized"])
        self.assertFalse(report["external_skill_execution_authorized"])


if __name__ == "__main__":
    unittest.main()
