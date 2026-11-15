import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nmsa.docker_log_triage import assess_log, safe_log_file, triage, SIGNALS


class DockerLogTriageTests(unittest.TestCase):
    def test_counts_redacted_categories_only(self):
        source = "secret token=abc123 backend exited unexpectedly; permission denied"
        result = assess_log(source)
        self.assertIn("backend_exit", result)
        self.assertGreaterEqual(result["backend_exit"], 1)
        self.assertNotIn("abc123", str(result))

    def test_noise_does_not_prove_root_cause(self):
        with tempfile.TemporaryDirectory() as temp:
            host = Path(temp) / "host"
            vm = Path(temp) / "vm"
            host.mkdir()
            vm.mkdir()
            (host / "com.docker.backend.exe.log").write_text(
                "backend exited unexpectedly; access denied password=PRIVATE", encoding="utf-8")
            with patch("nmsa.docker_log_triage.running_on_windows", return_value=True):
                result = triage(temp)
            self.assertEqual(result["status"], "REVIEW")
            self.assertFalse(result["root_cause_confirmed"])
            self.assertFalse(result["raw_logs_persisted"])
            self.assertNotIn("PRIVATE", str(result))

    def test_rejects_non_file_and_outside_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            a = Path(temp) / "a"
            b = Path(temp) / "b"
            a.mkdir()
            b.mkdir()
            file = b / "log.txt"
            file.write_text("private", encoding="utf-8")
            with self.assertRaises(ValueError):
                safe_log_file(file, a)

    def test_missing_logs_do_not_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("nmsa.docker_log_triage.running_on_windows", return_value=True):
                result = triage(temp)
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(result["logs_processed"], 0)

    def test_only_known_patterns(self):
        self.assertEqual(set(assess_log("hello")), set(SIGNALS))
        self.assertEqual(sum(assess_log("hello").values()), 0)

    def test_unknown_platform_blocks(self):
        with patch("nmsa.docker_log_triage.running_on_windows", return_value=False):
            result = triage()
        self.assertEqual(result["status"], "UNSUPPORTED_PLATFORM")


if __name__ == "__main__":
    unittest.main()
