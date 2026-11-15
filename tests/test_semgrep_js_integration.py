"""Integration: actual Semgrep invocation on locally authored positive/negative fixtures."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from nmsa.cli import run


class SemgrepJavascriptIntegration(unittest.TestCase):
    def test_javascript_security_rule_detection(self):
        exe = shutil.which("semgrep") or os.environ.get("NMSA_SEMGREP_BIN")
        if not exe or not Path(exe).is_file():
            self.skipTest("Semgrep CLI not installed in CI fixture environment")
        with tempfile.TemporaryDirectory() as t:
            target = Path(t)
            (target / "bad.js").write_text(
                "const output = eval(payload);\n"
                "const dynamic = new Function(payload);\n"
                "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"
                "const cp = require('child_process');\n"
                "cp.exec(command);\n"
                "response.setHeader('Access-Control-Allow-Origin', '*');\n",
                encoding="utf-8")
            (target / "clean.js").write_text(
                "export function sanitize(input) { return String(input).trim(); }\n",
                encoding="utf-8")
            result = run("semgrep", target, 120)
            self.assertEqual(result["status"], "COMPLETE", result["message"])
            rules = {f["rule"] for f in result["findings"]}
            expected = {
                "nmsa.js.eval-call", "nmsa.js.function-constructor",
                "nmsa.node.tls-verification-disabled",
                "nmsa.node.child-process-exec",
                "nmsa.vercel.api-wildcard-cors"}
            self.assertTrue(expected.issubset(rules), rules)
            self.assertFalse(any(f["path"] == "clean.js" for f in result["findings"]))
            self.assertFalse(any("D.NileMinds" in f["rule"] for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
