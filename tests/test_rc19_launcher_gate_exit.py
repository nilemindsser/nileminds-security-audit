"""The launcher-survival gate must never return CLI success for PID-only readiness."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from nmsa.cross_session_gate import main


class LauncherExitGateTests(unittest.TestCase):
    def test_cross_process_liveness_only_is_nonzero(self):
        data = {"status": "CROSS_PROCESS_LIVENESS_ONLY",
                "cross_process_verified": True,
                "cross_session_verified": False,
                "launcher_exit_verified": False,
                "isolation_verified": False}
        output = io.StringIO()
        with patch("nmsa.cross_session_gate.confirm", return_value=data):
            with contextlib.redirect_stdout(output):
                code = main(["--confirm", "unused-marker"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output.getvalue())["cross_session_verified"])

    def test_capture_only_returns_zero_for_capture(self):
        with patch("nmsa.cross_session_gate.capture", return_value={"status": "CAPTURED"}):
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["--capture", "unused-marker"])
        self.assertEqual(code, 0)

    def test_failed_confirm_returns_nonzero(self):
        with patch("nmsa.cross_session_gate.confirm", return_value={"status": "BLOCKED"}):
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["--confirm", "unused-marker"])
        self.assertEqual(code, 2)

    def test_successful_pid_check_cannot_be_release_proof(self):
        from nmsa.release_assurance import assess, RC13_EVIDENCE_SNAPSHOT
        result = assess(RC13_EVIDENCE_SNAPSHOT)
        self.assertIn("launcher_exit_persistence", result["blocking_gates"])
        self.assertFalse(result["production_authorized"])


if __name__ == "__main__":
    unittest.main()
