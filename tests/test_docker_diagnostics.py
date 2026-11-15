import unittest
from unittest.mock import patch

from nmsa.docker_diagnostics import CHECKS, diagnose, safe_run


def make_runner(context="desktop-linux", engine="linux", service="Stopped", wsl_ok=True):
    values = {
        "docker_context": {"ok": True, "output": context},
        "docker_server": {"ok": bool(engine), "output": engine},
        "docker_service": {"ok": True, "output": service},
        "wsl_engine": {"ok": wsl_ok, "output": "private-machine-data"},
    }
    def runner(argv):
        for key, command in CHECKS.items():
            if argv == command:
                return values[key]
        raise AssertionError("Unapproved command")
    return runner


class DockerDiagnosticsTests(unittest.TestCase):
    @patch("nmsa.docker_diagnostics.platform.system", return_value="Windows")
    def test_unavailable_engine_is_blocked(self, _):
        report = diagnose(runner=make_runner(engine=""))
        self.assertEqual(report["status"], "BLOCKED")
        self.assertFalse(report["isolation_verified"])
        self.assertFalse(report["container_executed"])

    @patch("nmsa.docker_diagnostics.platform.system", return_value="Windows")
    def test_alive_engine_is_not_isolation_pass(self, _):
        report = diagnose(runner=make_runner())
        self.assertEqual(report["status"], "LIVENESS_ONLY")
        self.assertFalse(report["isolation_verified"])

    @patch("nmsa.docker_diagnostics.platform.system", return_value="Windows")
    def test_unexpected_context_requires_review(self, _):
        report = diagnose(runner=make_runner(context="default"))
        self.assertEqual(report["status"], "REVIEW")

    @patch("nmsa.docker_diagnostics.platform.system", return_value="Windows")
    def test_unknown_outputs_not_leaked(self, _):
        report = diagnose(runner=make_runner(
            context="personal-secret-context", service="secret-admin", wsl_ok=True))
        self.assertNotIn("personal-secret-context", str(report))
        self.assertNotIn("secret-admin", str(report))
        self.assertNotIn("private-machine-data", str(report))

    @patch("nmsa.docker_diagnostics.platform.system", return_value="Linux")
    def test_non_windows_not_invoked(self, _):
        def forbidden(_argv):
            raise AssertionError("must not invoke command")
        self.assertEqual(diagnose(runner=forbidden)["status"], "UNSUPPORTED_PLATFORM")

    @patch("nmsa.docker_diagnostics.subprocess.run", side_effect=OSError("private path"))
    def test_spawn_failure_redacted(self, _):
        self.assertEqual(safe_run(["docker", "info"]), {"ok": False, "output": ""})

    @patch("nmsa.docker_diagnostics.subprocess.run")
    def test_no_shell_interpolation(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "linux"
        safe_run(CHECKS["docker_server"])
        self.assertFalse(run.call_args.kwargs["shell"])


if __name__ == "__main__":
    unittest.main()
