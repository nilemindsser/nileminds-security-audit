import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from nmsa.cli import main, parse, deduplicate, safe_path, markdown


class TestAudit(unittest.TestCase):
    def test_semgrep(self):
        r = parse("semgrep", {"results": [{"check_id": "x", "path": "a.py", "start": {"line": 3}, "extra": {"severity": "ERROR"}}]}, Path("."))
        self.assertEqual(r[0]["severity"], "ERROR")
        self.assertEqual(parse("semgrep", {"results": [{"check_id": "D.project.nmsa.python.eval-use", "path": "a.py"}]}, Path("."))[0]["rule"], "nmsa.python.eval-use")
    def test_gitleaks_does_not_leak_match(self):
        r = parse("gitleaks", [{"RuleID": "secret", "File": "a.txt", "StartLine": 4, "Secret": "DONOTPRINT"}], Path("."))
        self.assertNotIn("DONOTPRINT", str(r))
    def test_dedup_provenance(self):
        rows = [{"tool": "a", "rule": "x", "severity": "HIGH", "path": "a", "line": 1},
                {"tool": "b", "rule": "x", "severity": "HIGH", "path": "a", "line": 1}]
        self.assertEqual(deduplicate(rows)[0]["tools"], ["a", "b"])
    def test_outside_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(safe_path("/somewhere/outside", Path(tmp)), "[outside-target]")
    def test_missing_scanners_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target, output = root / "target", root / "output"
            target.mkdir(); output.mkdir()
            with patch("nmsa.cli.shutil.which", return_value=None):
                code = main([str(target), "--output", str(output)])
            self.assertEqual(code, 2)
            self.assertIn("INCOMPLETE", (output / "SECURITY-AUDIT.md").read_text())


if __name__ == "__main__":
    unittest.main()
