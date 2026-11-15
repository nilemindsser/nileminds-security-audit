import unittest
from nmsa.incident_review import analyze

D = {"status": "BLOCKED", "signals": {"linux_engine_available": False}}
T = {"status": "REVIEW", "recent_hour_buckets": [
    {"hour_utc": "2026-11-15T10:00Z", "source_count": 3, "signals": {"wsl_failure": 8, "permission_failure": 2}},
    {"hour_utc": "2026-11-10T22:00Z", "source_count": 1, "signals": {"wsl_failure": 1}},
]}


class IncidentReviewTests(unittest.TestCase):
    def test_blocked_with_prioritized_signals(self):
        r = analyze(D, T)
        self.assertEqual(r["status"], "BLOCKED")
        self.assertEqual(r["signal_ranking"][0], {"category": "wsl_failure", "observations": 9})
        self.assertEqual(r["multi_source_hour_windows"], 1)
        self.assertFalse(r["root_cause_confirmed"])
        self.assertFalse(r["remediation_authorized"])

    def test_liveness_still_incomplete(self):
        r = analyze({"status": "LIVENESS_ONLY", "signals": {"linux_engine_available": True}}, T)
        self.assertEqual(r["status"], "INCOMPLETE")
        self.assertFalse(r["isolation_verified"])

    def test_missing_logs_still_not_pass(self):
        r = analyze(D, {"status": "INCOMPLETE", "recent_hour_buckets": []})
        self.assertEqual(r["status"], "BLOCKED")
        self.assertEqual(r["signal_ranking"], [])

    def test_never_copies_untrusted_metadata(self):
        t = {**T, "private_raw_log": "SECRET DO NOT REPORT"}
        d = {**D, "raw_error": "password=DO_NOT_REPORT"}
        r = analyze(d, t)
        self.assertNotIn("DO_NOT_REPORT", str(r))

    def test_rejects_malicious_or_impossible_schema(self):
        t = {"status": "REVIEW", "recent_hour_buckets": [
            {"hour_utc": "2026-11-15T10:00Z", "source_count": 3,
             "signals": {"wsl_failure": 999999999}}]}
        with self.assertRaises(ValueError):
            analyze(D, t)
        t["recent_hour_buckets"][0]["signals"] = {"unknown_flag": 1}
        with self.assertRaises(ValueError):
            analyze(D, t)
        t["recent_hour_buckets"][0]["signals"] = {"wsl_failure": 2}
        t["recent_hour_buckets"][0]["hour_utc"] = "../../secrets"
        with self.assertRaises(ValueError):
            analyze(D, t)

    def test_no_fake_success_for_unknown_state(self):
        with self.assertRaises(ValueError):
            analyze({"status": "CERTIFIED", "signals": {}}, T)


if __name__ == "__main__":
    unittest.main()
