import unittest
from nmsa.release_assurance import FIELDS, RC13_EVIDENCE_SNAPSHOT, assess


class ReleaseAssuranceTests(unittest.TestCase):
    def test_known_evidence_blocks_unvalidated_production(self):
        r = assess(RC13_EVIDENCE_SNAPSHOT)
        self.assertEqual(r["status"], "BLOCKED")
        self.assertIn("launcher_exit_persistence", r["blocking_gates"])
        self.assertIn("independent_security_review", r["blocking_gates"])
        self.assertFalse(r["security_certified"])
        self.assertFalse(r["production_authorized"])
        self.assertFalse(r["external_skill_execution_authorized"])

    def test_all_pass_remains_independent_review_only(self):
        r = assess({name: "PASS" for name in FIELDS})
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assertEqual(r["blocking_gates"], [])
        self.assertTrue(r["independent_review_required"])
        self.assertFalse(r["production_authorized"])

    def test_ci_only_pass_not_enough(self):
        data = {name: "NOT_RUN" for name in FIELDS}
        data["code_ci"] = "PASS"
        data["synthetic_rule_benchmark"] = "PASS"
        r = assess(data)
        self.assertEqual(r["status"], "BLOCKED")
        self.assertEqual(len(r["blocking_gates"]), len(FIELDS)-2)

    def test_real_container_pass_does_not_prove_launcher_lifetime(self):
        data = {name: "PASS" for name in FIELDS}
        data["launcher_exit_persistence"] = "FAIL"
        r = assess(data)
        self.assertEqual(r["blocking_gates"], ["launcher_exit_persistence"])

    def test_no_new_or_missing_fields(self):
        with self.assertRaises(ValueError):
            assess({"code_ci": "PASS"})
        with self.assertRaises(ValueError):
            assess({**RC13_EVIDENCE_SNAPSHOT, "raw_log": "secret"})

    def test_invalid_states_fail_closed(self):
        for state in (True, False, 1, "APPROVED", "PASS\npassword=abc", None):
            data = dict(RC13_EVIDENCE_SNAPSHOT)
            data["owner_release_decision"] = state
            with self.assertRaises(ValueError):
                assess(data)

    def test_output_contains_no_machine_sensitive_detail(self):
        report = assess(RC13_EVIDENCE_SNAPSHOT)
        self.assertEqual(set(report["blocking_gates"]) <= set(FIELDS), True)
        self.assertNotIn("D:\\", str(report))
        self.assertNotIn("token=", str(report))

    def test_failed_external_skill_review_always_blocks(self):
        data = {name: "PASS" for name in FIELDS}
        data["independent_security_review"] = "FAIL"
        self.assertIn("independent_security_review", assess(data)["blocking_gates"])


if __name__ == "__main__":
    unittest.main()
