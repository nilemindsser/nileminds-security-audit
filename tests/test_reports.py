import unittest
from nmsa.reports import sarif, html


class TestReports(unittest.TestCase):
    def setUp(self):
        self.report = {
            "status": "FAIL",
            "scanners": [{"tool": "semgrep", "status": "COMPLETE", "findings": [1]},
                         {"tool": "gitleaks", "status": "NOT_INSTALLED", "findings": []}],
            "findings": [{"severity": "HIGH", "rule": "<script>alert(1)</script>",
                          "path": "src/<bad>.py", "line": 10, "tools": ["semgrep"]}],
        }

    def test_html_escapes(self):
        doc = html(self.report)
        self.assertIn("&lt;script&gt;", doc)
        self.assertNotIn("<script>", doc)
        self.assertIn("NOT_INSTALLED", doc)

    def test_sarif_schema(self):
        doc = sarif(self.report)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"]), 2)
        semgrep = next(x for x in doc["runs"] if x["tool"]["driver"]["name"] == "semgrep")
        self.assertEqual(semgrep["results"][0]["level"], "error")
        self.assertEqual(semgrep["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 10)


if __name__ == "__main__":
    unittest.main()
