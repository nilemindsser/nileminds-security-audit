"""Semgrep taint regression: stable rule IDs and negative data-flow cases."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from nmsa.cli import run


class TaintRuleTests(unittest.TestCase):
    def test_taint_intermediate_and_unrelated_payload(self):
        exe = os.environ.get("NMSA_SEMGREP_BIN") or shutil.which("semgrep")
        if not exe or not Path(exe).is_file():
            self.skipTest("Semgrep not installed; verified separately in pinned benchmark CI")
        with tempfile.TemporaryDirectory(prefix="nmsa-taint-") as tmp:
            source = Path(tmp)
            (source / "flow.js").write_text(
                'async function writeA(put, path, data) { const body = JSON.stringify(data); '
                'await put(path, body, {access:"public", allowOverwrite:true}); }\n'
                'async function writeB(put, path, data) { const body = JSON.stringify(data); '
                'await put(path, body, {access:"private", allowOverwrite:true}); }\n'
                'async function writeC(put, path, data) { const body = JSON.stringify(data); '
                'await put(path, "public-info", {access:"public", allowOverwrite:true}); }\n',
                encoding="utf-8",
            )
            report = run("semgrep", source, 120)
            self.assertEqual(report["status"], "COMPLETE")
            matches = [f for f in report["findings"]
                       if f["rule"] == "nmsa.storage.json-to-public-blob-same-function"]
            self.assertEqual(len(matches), 1, matches)
            self.assertEqual(matches[0]["line"], 1)
            self.assertEqual(matches[0]["path"], "flow.js")


if __name__ == "__main__":
    unittest.main()
