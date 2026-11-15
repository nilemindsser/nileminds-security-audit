"""Reproducible Semgrep precision/recall on *synthetic*, independently labeled rule fixtures.

This evaluates exact rule matching, not real-world vulnerability exploitability.
Never executes fixture code; no network lookups or dynamic dependency installs.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import shutil
import tempfile
from .cli import run

# Every case is one rule/test pair in a separate file, allowing transparent
# true-positive, false-positive, false-negative, true-negative accounting.
CASES = (
    ("eval-positive", "nmsa.js.eval-call", True, "const result = eval(userInput);\n"),
    ("eval-negative", "nmsa.js.eval-call", False, "const result = JSON.parse(userInput);\n"),
    ("function-positive", "nmsa.js.function-constructor", True, "const fn = new Function(userInput);\n"),
    ("function-negative", "nmsa.js.function-constructor", False, "const fn = (input) => String(input);\n"),
    ("tls-positive", "nmsa.node.tls-verification-disabled", True, 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n'),
    ("tls-negative", "nmsa.node.tls-verification-disabled", False, 'process.env.NODE_ENV = "test";\n'),
    ("shell-positive", "nmsa.node.child-process-exec", True, 'const cp = require("child_process"); cp.exec(userInput);\n'),
    ("shell-negative", "nmsa.node.child-process-exec", False, 'const cp = require("child_process"); cp.spawn("node", ["--version"]);\n'),
    ("cors-positive", "nmsa.vercel.api-wildcard-cors", True, 'res.setHeader("Access-Control-Allow-Origin", "*");\n'),
    ("cors-negative", "nmsa.vercel.api-wildcard-cors", False, 'res.setHeader("Access-Control-Allow-Origin", "https://example.test");\n'),
    ("blob-positive", "nmsa.node.public-blob-data-write", True, 'async function save(put, name, body) { await put("data/" + name, body, {access: "public", allowOverwrite: true}); }\n'),
    ("blob-negative", "nmsa.node.public-blob-data-write", False, 'async function save(put, name, body) { await put("uploads/" + name, body, {access: "public"}); }\n'),

    ("jsonblob-positive", "nmsa.storage.public-blob-json-object", True, 'async function write(put, name, data) { await put(name, JSON.stringify(data), {access: "public", addRandomSuffix: false}); }\n'),
    ("jsonblob-negative", "nmsa.storage.public-blob-json-object", False, 'async function write(put, name, data) { await put(name, JSON.stringify(data), {access: "private", addRandomSuffix: false}); }\n'),
    ("cookie-positive", "nmsa.node.cookie-http-only-disabled", True, 'res.cookie("session", value, {httpOnly: false, sameSite: "lax"});\n'),
    ("cookie-negative", "nmsa.node.cookie-http-only-disabled", False, 'res.cookie("session", value, {httpOnly: true, sameSite: "lax"});\n'),

    ("taint-variable-positive", "nmsa.storage.json-to-public-blob-same-function", True, 'async function save(put, path, obj) { const body = JSON.stringify(obj); await put(path, body, {access:"public", allowOverwrite:true}); }\n'),
    ("taint-variable-negative", "nmsa.storage.json-to-public-blob-same-function", False, 'async function save(put, path, obj) { const body = JSON.stringify(obj); await put(path, body, {access:"private", allowOverwrite:true}); }\n'),
    ("taint-other-variable-negative", "nmsa.storage.json-to-public-blob-same-function", False, 'async function save(put, path, obj) { const body = JSON.stringify(obj); const publicBody = "public marketing content"; await put(path, publicBody, {access:"public", allowOverwrite:true}); }\n'),
    ("taint-json-inline-positive", "nmsa.storage.json-to-public-blob-same-function", True, 'async function save(put, path, obj) { await put(path, JSON.stringify(obj), {access:"public", allowOverwrite:true}); }\n'),

)


def calculate(cases, observed):
    """A case is a success when its *expected rule* fires in its own file.
    Other rule signals are kept as incidental and never silently counted as TP.
    """
    results = []
    totals = defaultdict(int)
    for case_id, rule, expected, _ in cases:
        fired = rule in observed.get(case_id, set())
        outcome = ("TP" if expected else "FP") if fired else ("FN" if expected else "TN")
        totals[outcome] += 1
        results.append({"case_id": case_id, "expected_rule": rule, "positive": expected,
                        "detected": fired, "outcome": outcome})
    tp, fp, fn = totals["TP"], totals["FP"], totals["FN"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {"total": len(results), "TP": tp, "FP": fp, "FN": fn, "TN": totals["TN"],
            "precision": precision, "recall": recall, "cases": results}


def benchmark():
    with tempfile.TemporaryDirectory(prefix="nmsa-benchmark-") as folder:
        project = Path(folder)
        for case_id, _, _, code in CASES:
            (project / (case_id + ".js")).write_text(code, encoding="utf-8")
        scan = run("semgrep", project, 180)
        if scan["status"] != "COMPLETE":
            return {"status": "INCOMPLETE", "reason": scan["status"]}
        observed = defaultdict(set)
        for row in scan["findings"]:
            stem = Path(row["path"]).stem
            observed[stem].add(row["rule"])
        metrics = calculate(CASES, observed)
        metrics["status"] = "FIXTURE_BENCHMARK_COMPLETE"
        metrics["note"] = "Synthetic labeled pattern fixtures only. Not an estimate of real-world vulnerability recall, false positives or exploitability."
        return metrics


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reproducible, local synthetic Semgrep benchmark")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    target = Path(args.output).resolve()
    if not target.parent.is_dir():
        parser.error("Existing output parent required")
    result = benchmark()
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result.get(k) for k in ("status", "total", "TP", "FP", "FN", "TN", "precision", "recall")}))
    return 0 if result["status"] == "FIXTURE_BENCHMARK_COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
