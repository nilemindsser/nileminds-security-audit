import unittest
from unittest.mock import patch
from nmsa.wsl_engine_probe import COMMANDS, check, differential


class WslEngineProbeTests(unittest.TestCase):
    def test_wsl_ok_docker_down_is_review_not_wsl_failure(self):
        allowed = {id(COMMANDS["wsl_ubuntu"]), id(COMMANDS["wsl_docker"])}
        r = differential(checker=lambda cmd: id(cmd) in allowed, system=lambda: "Windows")
        self.assertEqual(r["status"], "DOCKER_BACKEND_REVIEW")
        self.assertFalse(r["observations"]["docker_engine"])
        self.assertFalse(r["root_cause_confirmed"])
        self.assertFalse(r["remediation_authorized"])

    def test_unavailable_docker_distro_never_claims_backend_failure(self):
        r = differential(checker=lambda cmd: cmd is COMMANDS["wsl_ubuntu"],
                         system=lambda: "Windows")
        self.assertEqual(r["status"], "WSL_OR_DOCKER_DISTRO_REVIEW")

    def test_engine_success_only_liveness(self):
        r = differential(checker=lambda _: True, system=lambda: "Windows")
        self.assertEqual(r["status"], "LIVENESS_ONLY")
        self.assertFalse(r["isolation_verified"])

    def test_non_windows_no_probe(self):
        def forbidden(_):
            raise AssertionError("No execution")
        self.assertEqual(differential(checker=forbidden, system=lambda: "Linux")["status"],
                         "UNSUPPORTED_PLATFORM")

    def test_failure_never_echoes_process_output(self):
        with patch("nmsa.wsl_engine_probe.subprocess.run") as proc:
            proc.return_value.returncode = 1
            proc.return_value.stdout = "password=SECRET"
            proc.return_value.stderr = "sensitive path"
            self.assertFalse(check(COMMANDS["wsl_docker"]))
            self.assertFalse(proc.call_args.kwargs["shell"])

    def test_only_fixed_read_only_subcommands(self):
        for name, cmd in COMMANDS.items():
            self.assertNotIn("--unregister", cmd)
            self.assertNotIn("--shutdown", cmd)
            self.assertNotIn("run", cmd)
            self.assertNotIn("--import", cmd)
        self.assertEqual(len(COMMANDS), 3)


if __name__ == "__main__":
    unittest.main()
