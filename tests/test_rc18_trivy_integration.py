"""Integration regression: main scanner must honor RC16 stale DB fail-closed gate."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from nmsa.cli import run, main


class TrivyIntegrationTests(unittest.TestCase):
    def test_expired_db_never_runs_scanner(self):
        version = Mock(returncode=0,
            stdout="Version: 0.76.2\nNextUpdate: 2026-11-15 07:01:20.721 +0000 UTC")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("nmsa.cli.shutil.which", return_value="trivy"), patch(
                "nmsa.cli.subprocess.run", return_value=version) as subprocess_run:
                report = run("trivy", Path(tmp), 30)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["findings"], [])
        self.assertEqual(subprocess_run.call_count, 1)

    def test_unverifiable_db_metadata_never_runs_scanner(self):
        version = Mock(returncode=0, stdout="Trivy Version: 0.1")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("nmsa.cli.shutil.which", return_value="trivy"), patch(
                "nmsa.cli.subprocess.run", return_value=version) as subprocess_run:
                report = run("trivy", Path(tmp), 30)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(subprocess_run.call_count, 1)

    def test_clean_looking_empty_results_not_complete(self):
        future = "NextUpdate: 2090-01-01 00:00:00 +0000 UTC"
        result = [
            Mock(returncode=0, stdout=future),
            Mock(returncode=0, stdout='{"Results": []}'),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            with patch("nmsa.cli.shutil.which", return_value="trivy"), patch(
                "nmsa.cli.subprocess.run", side_effect=result) as runner:
                report = run("trivy", Path(tmp), 30)
        self.assertEqual(report["status"], "INCOMPLETE")
        args = runner.call_args.args[0]
        self.assertIn("--offline-scan", args)
        self.assertIn("--skip-db-update", args)
        self.assertIn("--skip-java-db-update", args)
        self.assertFalse(runner.call_args.kwargs["shell"])

    def test_current_db_with_explicit_coverage_needs_review_not_guarantee(self):
        result = [
            Mock(returncode=0, stdout="NextUpdate: 2090-01-01 00:00:00 +0000 UTC"),
            Mock(returncode=0, stdout=json.dumps({
                "Results": [{"Target": "fixture", "Type": "python-pkg", "Vulnerabilities": []}]
            })),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            with patch("nmsa.cli.shutil.which", return_value="trivy"), patch(
                "nmsa.cli.subprocess.run", side_effect=result):
                report = run("trivy", Path(tmp), 30)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(report["findings"], [])

    def test_full_audit_cannot_pass_with_stale_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, out = Path(tmp) / "source", Path(tmp) / "output"
            src.mkdir()
            out.mkdir()
            ver = Mock(returncode=0,
                stdout="NextUpdate: 2026-11-15 07:01:20 +0000 UTC")
            with patch("nmsa.cli.shutil.which", return_value="trivy"), patch(
                "nmsa.cli.subprocess.run", return_value=ver):
                code = main([str(src), "--output", str(out), "--tools", "trivy"])
            self.assertEqual(code, 2)
            report = json.loads((out / "security-audit.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertNotIn("password", json.dumps(report))
            self.assertEqual(report["scanners"][0]["status"], "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
