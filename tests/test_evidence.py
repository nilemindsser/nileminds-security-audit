import unittest
from nmsa.evidence import classify, summarize


class EvidenceTests(unittest.TestCase):
    def test_scanner_signal_never_confirmed(self):
        self.assertEqual(summarize([{"rule": "x"}])["confirmed"], 0)

    def test_claim_without_evidence_fails_closed(self):
        self.assertEqual(classify({"status": "VALIDATED_IN_STAGING"})["status"], "NEEDS_VALIDATION")

    def test_production_validation_rejected(self):
        r = {"status": "VALIDATED_IN_STAGING", "reviewer": "independent",
             "target_revision": "abc", "reproduction_reference": "fixture1",
             "impact_reference": "case1", "environment": "production",
             "independently_verified": True}
        self.assertEqual(classify(r)["status"], "NEEDS_VALIDATION")

    def test_metadata_recorded_but_not_trusted(self):
        r = {"status": "VALIDATED_IN_STAGING", "reviewer": "independent",
             "target_revision": "abc", "reproduction_reference": "fixture1",
             "impact_reference": "case1", "environment": "non-production",
             "independently_verified": True}
        self.assertEqual(classify(r)["status"], "VALIDATED_IN_STAGING")

    def test_false_positive_requires_evidence(self):
        self.assertEqual(classify({"status": "FALSE_POSITIVE"})["status"], "NEEDS_VALIDATION")

    def test_invalid_state_rejected(self):
        with self.assertRaises(ValueError):
            classify({"status": "AUTO_CONFIRMED"})


if __name__ == "__main__":
    unittest.main()
