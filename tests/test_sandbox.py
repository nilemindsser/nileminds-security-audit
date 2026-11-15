import unittest
from unittest.mock import patch
from nmsa.sandbox import SandboxSpec, docker_command, readiness, run_fixture


VALID_IMAGE = "sha256:" + "a" * 64


class SandboxTests(unittest.TestCase):
    def test_mandatory_restrictions(self):
        cmd = docker_command(image_id=VALID_IMAGE)
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
            docker_command(SandboxSpec(image="ubuntu:latest"), image_id=VALID_IMAGE)

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
        with patch("nmsa.sandbox.verify_runtime", return_value={"status": "STABLE_FOR_FIXTURE_PRECHECK"}), patch.dict(
                "os.environ", {"NMSA_SANDBOX_IMAGE_ID": VALID_IMAGE}), patch(
                "nmsa.sandbox.shutil.which", return_value="docker"), patch(
                "nmsa.sandbox.subprocess.run", side_effect=[Result(), NotFound()]) as run:
            self.assertEqual(run_fixture()["reason"], "image_id_not_verified_locally")
            self.assertEqual(run.call_count, 2)

    def test_unpinned_image_rejected(self):
        for image_id in ("python:latest", "sha256:123", "sha256:" + "z" * 64, ""):
            with self.subTest(image_id=image_id), self.assertRaises(ValueError):
                docker_command(image_id=image_id)

    def test_missing_explicit_id_blocks_before_run(self):
        with patch("nmsa.sandbox.verify_runtime", return_value={"status": "STABLE_FOR_FIXTURE_PRECHECK"}), patch.dict(
                "os.environ", {"NMSA_SANDBOX_IMAGE_ID": ""}), patch(
                "nmsa.sandbox.shutil.which", return_value="docker"), patch(
                "nmsa.sandbox.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "linux"
            self.assertEqual(run_fixture()["reason"], "immutable_image_id_required")
            self.assertEqual(run.call_count, 1)

    def test_mismatched_local_image_id_blocks(self):
        class Result:
            returncode = 0
            stdout = "linux"
        class WrongImage:
            returncode = 0
            stdout = "sha256:" + "b" * 64
        with patch("nmsa.sandbox.verify_runtime", return_value={"status": "STABLE_FOR_FIXTURE_PRECHECK"}), patch.dict(
                "os.environ", {"NMSA_SANDBOX_IMAGE_ID": VALID_IMAGE}), patch(
                "nmsa.sandbox.shutil.which", return_value="docker"), patch(
                "nmsa.sandbox.subprocess.run", side_effect=[Result(), WrongImage()]) as run:
            self.assertEqual(run_fixture()["reason"], "image_id_not_verified_locally")
            self.assertEqual(run.call_count, 2)

    def test_no_tool_execution_when_daemon_missing(self):
        with patch("nmsa.sandbox.shutil.which", return_value=None), patch(
                "nmsa.sandbox.subprocess.run") as run:
            self.assertEqual(run_fixture()["status"], "BLOCKED")
            run.assert_not_called()

    def test_fixture_has_no_host_mounts_or_user_script(self):
        cmd = docker_command(image_id=VALID_IMAGE)
        self.assertEqual(cmd[-5:-3], ["python", "-I"])
        self.assertEqual(cmd[-1], "print('NMSA_SANDBOX_FIXTURE_OK')")
        self.assertTrue(all("nmsa-sources" not in x for x in cmd))
        self.assertIn("--pull", cmd)
        self.assertIn("never", cmd)
        self.assertIn(VALID_IMAGE, cmd)
        self.assertNotIn("python:3.12.9-alpine3.21", cmd)


if __name__ == "__main__":
    unittest.main()

