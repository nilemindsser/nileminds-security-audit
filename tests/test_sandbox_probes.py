import json
import unittest
from unittest.mock import patch
from nmsa import sandbox
from nmsa.sandbox_probes import EXPECTED, PROBE, inspect_result, run_probes

IMAGE = "sha256:" + "a" * 64


class SandboxNegativeProbeTests(unittest.TestCase):
    def test_all_pass_still_not_certified(self):
        result = inspect_result(json.dumps({key: True for key in EXPECTED}))
        self.assertEqual(result["status"], "NEGATIVE_PROBES_PASS")
        self.assertFalse(result["isolation_verified"])
        self.assertEqual(result["passed_checks"], 7)

    def test_detects_real_failure_without_echoing_payload(self):
        result = inspect_result(json.dumps({key: key != "outbound_blocked" for key in EXPECTED}))
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["failed_checks"], ["outbound_blocked"])

    def test_broken_schema_rejected(self):
        for value in ("NOTJSON", "{}", "[]", '{"non_root":true}'):
            with self.subTest(value=value):
                self.assertEqual(inspect_result(value)["status"], "FAIL")

    def test_runtime_blocked_before_inspect_or_run(self):
        with patch("nmsa.sandbox_probes.sandbox.readiness", return_value={"status": "BLOCKED"}), patch(
                "nmsa.sandbox_probes.subprocess.run") as process:
            self.assertEqual(run_probes()["status"], "BLOCKED")
            process.assert_not_called()

    def test_no_image_id_no_execution(self):
        with patch("nmsa.sandbox_probes.sandbox.readiness", return_value={"status": "READY_FOR_FIXTURE"}), patch(
                "nmsa.sandbox_probes.verify_runtime", return_value={"status": "STABLE_FOR_FIXTURE_PRECHECK"}), patch.dict(
                "os.environ", {"NMSA_SANDBOX_IMAGE_ID": ""}), patch(
                "nmsa.sandbox_probes.subprocess.run") as process:
            self.assertEqual(run_probes()["reason"], "immutable_image_id_required")
            process.assert_not_called()

    def test_mismatched_image_prevents_container_run(self):
        class Mismatch:
            returncode = 0
            stdout = "sha256:" + "b" * 64
        with patch("nmsa.sandbox_probes.sandbox.readiness", return_value={"status": "READY_FOR_FIXTURE"}), patch(
                "nmsa.sandbox_probes.verify_runtime", return_value={"status": "STABLE_FOR_FIXTURE_PRECHECK"}), patch.dict(
                "os.environ", {"NMSA_SANDBOX_IMAGE_ID": IMAGE}), patch(
                "nmsa.sandbox_probes.subprocess.run", return_value=Mismatch()) as process:
            self.assertEqual(run_probes()["reason"], "local_image_id_mismatch")
            self.assertEqual(process.call_count, 1)

    def test_probe_command_inherits_restrictions_no_mounts(self):
        command = sandbox.docker_command(image_id=IMAGE)
        command[-1] = PROBE
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertIn("--read-only", command)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("--mount", command)
        self.assertNotIn("--env-file", command)
        self.assertEqual(command[command.index("--pull") + 1], "never")
        self.assertTrue(command[-1].startswith("import json,os,socket"))


if __name__ == "__main__":
    unittest.main()
