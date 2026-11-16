"""Every configured scanner must provide valid structured coverage."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from nmsa.cli import run


class ScannerSchemaTests(unittest.TestCase):
    def test_semgrep_empty_or_unstructured_report_blocks(self):
        for output in ("", "{}", "[]", '{"results":"not a list"}', '{"errors":[]}', '{"results":[],"errors":{}}'):
            with self.subTest(output=output):
                with tempfile.TemporaryDirectory() as tmp:
                    with patch("nmsa.cli.shutil.which", return_value="semgrep"), patch(
                        "nmsa.cli.subprocess.run",
                        return_value=Mock(returncode=0, stdout=output, stderr="SECRET")):
                        report = run("semgrep", Path(tmp), 30)
                self.assertNotEqual(report["status"], "COMPLETE")
                self.assertEqual(report["findings"], [])
                self.assertNotIn("SECRET", str(report))

    def test_semgrep_valid_empty_results_is_completed_but_not_certified(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("nmsa.cli.shutil.which", return_value="semgrep"), patch(
                "nmsa.cli.subprocess.run",
                return_value=Mock(returncode=0, stdout='{"results":[],"errors":[]}', stderr="")):
                report = run("semgrep", Path(tmp), 30)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(report["findings"], [])

    def test_gitleaks_missing_or_wrong_type_not_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("nmsa.cli.shutil.which", return_value="gitleaks"), patch(
                "nmsa.cli.subprocess.run",
                return_value=Mock(returncode=0, stdout="", stderr="")):
                report = run("gitleaks", Path(tmp), 30)
        self.assertNotEqual(report["status"], "COMPLETE")
        self.assertEqual(report["findings"], [])

    def test_gitleaks_non_list_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("nmsa.cli.shutil.which", return_value="gitleaks"), patch(
                "nmsa.cli.subprocess.run",
                return_value=Mock(returncode=0, stdout='{"something":"bad"}', stderr="")):
                report = run("gitleaks", Path(tmp), 30)
        self.assertNotEqual(report["status"], "COMPLETE")


if __name__ == "__main__":
    unittest.main()
