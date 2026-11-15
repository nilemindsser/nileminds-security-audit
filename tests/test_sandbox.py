import unittest
from unittest.mock import patch
from nmsa.sandbox import SandboxSpec, docker_command, readiness, run_fixture


class SandboxTests(unittest.TestCase):
    def test_mandatory_restrictions(self):
        cmd = docker_command()
        for x in ("--network", "none", "--read-only", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges:true", "--pids-limit",
                  "--memory", "--cpus", "--user", "65534:65534", "--tmpfs"):
            self.assertIn(x, cmd)
        self.assertNotIn("--privileged", cmd)
        self.assertNotIn("--mount", cmd)
        self.assertNotIn("--volume", cmd)
        self.assertNotIn("-v", cmd)
        self.assertNotIn("--env-file", cmd)
        self.assertNotIn("--device", cmd)

    def test_custom_profile_blocked(self):
        with self.assertRaises(ValueError):
            docker_command(SandboxSpec(image="ubuntu:latest"))

    def test_daemon_unavailable_blocked(self):
        with patch("nmsa.sandbox.shutil.which", return_value="docker"), patch(
                "nmsa.sandbox.subprocess.run", side_effect=OSError("unavailable")):
            self.assertEqual(readiness()["status"], "BLOCKED")

    def test_missing_image_does_not_run_fixture(self):
        class Result:
            returncode = 0
            stdout = "linux\n"
        class NotFound:
            returncode = 1
            stdout = ""
        with patch("nmsa.sandbox.shutil.which", return_value="docker"), patch(
                "nmsa.sandbox.subprocess.run", side_effect=[Result(), NotFound()]) as run:
            self.assertEqual(run_fixture()["reason"], "fixture_image_not_preloaded")
            self.assertEqual(run.call_count, 2)

    def test_no_tool_execution_when_daemon_missing(self):
        with patch("nmsa.sandbox.shutil.which", return_value=None), patch(
                "nmsa.sandbox.subprocess.run") as run:
            self.assertEqual(run_fixture()["status"], "BLOCKED")
            run.assert_not_called()

    def test_fixture_has_no_host_mounts_or_user_script(self):
        cmd = docker_command()
        self.assertEqual(cmd[-5:-3], ["python", "-I"])
        self.assertEqual(cmd[-1], "print('NMSA_SANDBOX_FIXTURE_OK')")
        self.assertTrue(all("nmsa-sources" not in x for x in cmd))


if __name__ == "__main__":
    unittest.main()

