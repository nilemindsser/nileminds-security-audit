"""Bounded detection test for NMSA's public Vercel Blob audit signal.

All fixture code is authored in this repository. The test never executes it,
contacts a network service, or accesses production data.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

RULES = Path(__file__).resolve().parents[1] / "nmsa" / "rules.yml"
BAD = """
async function writePrivateRecord(put, name, payload) {
  await put("data/" + name, JSON.stringify(payload), {
    access: "public", allowOverwrite: true
  });
}
"""
GOOD = """
async function saveImage(put, name, payload) {
  await put("uploads/" + name, payload, {access: "public"});
}
async function savePrivateRecord(put, name, payload) {
  await put("data/" + name, payload, {access: "private"});
}
"""


class BlobAuditRuleTests(unittest.TestCase):
    def test_rule_is_present(self):
        content = RULES.read_text(encoding="utf-8")
        self.assertIn("nmsa.node.public-blob-data-write", content)
        self.assertIn('access: "public"', content)

    def test_semgrep_detects_data_not_public_images(self):
        exe = os.environ.get("NMSA_SEMGREP_BIN") or shutil.which("semgrep")
        if not exe or not Path(exe).is_file():
            self.skipTest("Semgrep not installed: static presence test still runs")
        with tempfile.TemporaryDirectory(prefix="nmsa-blob-fixture-") as td:
            path = Path(td) / "fixture.js"
            path.write_text(BAD + GOOD, encoding="utf-8")
            cmd = [
                exe, "scan", "--config", str(RULES), "--json",
                "--metrics", "off", "--disable-version-check", str(path),
            ]
            completed = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=40, check=False,
            )
            self.assertIn(completed.returncode, (0, 1))
            report = json.loads(completed.stdout)
            self.assertEqual(report.get("errors"), [])
            matched = [v for v in report["results"] if "public-blob-data-write" in v["check_id"]]
            self.assertEqual(len(matched), 1, matched)
            self.assertEqual(matched[0]["start"]["line"], 3)


if __name__ == "__main__":
    unittest.main()
