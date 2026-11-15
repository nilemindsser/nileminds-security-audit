import unittest
from unittest.mock import patch
from nmsa.runtime_gate import sample, verify
from nmsa.sandbox import run_fixture


class DaemonResult:
    returncode = 0
    stdout = "linux 29.9.2"


class FailedResult:
    returncode = 1
    stdout = ""


class RuntimeGateTests(unittest.TestCase):
    def test_three_successful_samples_are_only_precheck(self):
        with patch("nmsa.runtime_gate.sample", side_effect=[
                {"ok": True, "reason": "ok"}] * 3), patch(
                "nmsa.runtime_gate.time.sleep") as sleeper:
            result = verify(samples=3, delay=0, sleeper=sleeper)
        self.assertEqual(result["status"], "STABLE_FOR_FIXTURE_PRECHECK")
        self.assertFalse(result["isolation_verified"])
        self.assertEqual(result["passed_samples"], 3)

    def test_transient_daemon_failure_fails_closed(self):
        statuses = [{"ok": True, "reason": "ok"},
                    {"ok": False, "reason": "daemon_unavailable"},
                    {"ok": True, "reason": "ok"}]
        with patch("nmsa.runtime_gate.sample", side_effect=statuses) as probe:
            result = verify(samples=3, delay=0, sleeper=lambda _: None)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["passed_samples"], 1)
        self.assertEqual(probe.call_count, 2)

    def test_docker_command_not_called_when_unstable(self):
        with patch("nmsa.sandbox.readiness", return_value={
                "status": "READY_FOR_FIXTURE"}), patch(
                "nmsa.sandbox.verify_runtime", return_value={
                "status": "BLOCKED"}), patch(
                "nmsa.sandbox.subprocess.run") as docker:
            result = run_fixture()
        self.assertEqual(result["reason"], "docker_daemon_not_stable")
        docker.assert_not_called()

    def test_cli_missing_blocks(self):
        with patch("nmsa.runtime_gate.shutil.which", return_value=None):
            self.assertEqual(sample()["reason"], "docker_cli_missing")

    def test_linux_info_required(self):
        with patch("nmsa.runtime_gate.shutil.which", return_value="docker"), patch(
                "nmsa.runtime_gate.subprocess.run", return_value=FailedResult()):
            self.assertFalse(sample()["ok"])
        with patch("nmsa.runtime_gate.shutil.which", return_value="docker"), patch(
                "nmsa.runtime_gate.subprocess.run", return_value=DaemonResult()):
            self.assertTrue(sample()["ok"])

    def test_no_user_supplied_commands(self):
        with self.assertRaises(ValueError):
            verify(samples=100, sleeper=lambda _: None)
        with self.assertRaises(ValueError):
            verify(samples=3, delay=100, sleeper=lambda _: None)


if __name__ == "__main__":
    unittest.main()
