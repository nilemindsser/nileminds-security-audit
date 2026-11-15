import json
import unittest
from unittest.mock import patch

from nmsa.node_sandbox_probe import PROBE_JS, command, evaluate, run, EXPECTED

ID = "sha256:" + "a" * 64


class NodeFixtureTests(unittest.TestCase):
    def test_requires_restricted_docker_invocation(self):
        c = command(ID)
        self.assertIn("--network", c)
        self.assertEqual(c[c.index("--network") + 1], "none")
        self.assertIn("--read-only", c)
        self.assertEqual(c[c.index("--pull") + 1], "never")
        self.assertIn("--cap-drop", c)
        self.assertNotIn("--privileged", c)
        self.assertNotIn("--mount", c)
        self.assertEqual(c[-3:], ["node", "-e", PROBE_JS])
        self.assertEqual(c[-4], ID)

    def test_untrusted_image_id_rejected(self):
        with self.assertRaises(ValueError):
            command("node:latest")

    def test_pass_not_certification(self):
        report = evaluate(json.dumps({k: True for k in EXPECTED}))
        self.assertEqual(report["status"], "NEGATIVE_PROBES_PASS")
        self.assertFalse(report["isolation_verified"])
        self.assertEqual(report["passed_checks"], 7)

    def test_failed_checks_reported(self):
        report = evaluate(json.dumps({k: k != "outbound_blocked" for k in EXPECTED}))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failed_checks"], ["outbound_blocked"])

    def test_malformed_result_fail_closed(self):
        for value in ("not json", "{}", "[]", '{"non_root":1}'):
            self.assertEqual(evaluate(value)["status"], "FAIL")

    def test_no_image_blocks_without_docker(self):
        with patch.dict("os.environ", {"NMSA_SANDBOX_IMAGE_ID": ""}), patch(
                "nmsa.node_sandbox_probe.subprocess.run") as proc:
            self.assertEqual(run()["status"], "BLOCKED")
            proc.assert_not_called()

    def test_engine_failure_blocks_before_docker(self):
        with patch.dict("os.environ", {"NMSA_SANDBOX_IMAGE_ID": ID}), patch(
                "nmsa.node_sandbox_probe.verify", return_value={"status": "BLOCKED"}), patch(
                "nmsa.node_sandbox_probe.subprocess.run") as proc:
            self.assertEqual(run()["reason"], "unstable_linux_daemon")
            proc.assert_not_called()

    def test_image_mismatch_no_container_run(self):
        class Result:
            returncode = 0
            stdout = "sha256:" + "b" * 64
        with patch.dict("os.environ", {"NMSA_SANDBOX_IMAGE_ID": ID}), patch(
                "nmsa.node_sandbox_probe.verify", return_value={"status": "STABLE_FOR_FIXTURE_PRECHECK"}), patch(
                "nmsa.node_sandbox_probe.subprocess.run", return_value=Result()) as proc:
            self.assertEqual(run()["reason"], "image_id_not_preloaded_or_mismatch")
            self.assertEqual(proc.call_count, 1)


if __name__ == "__main__":
    unittest.main()
