"""Opt-in, local-only, non-destructive API security contract probes.

Only http://127.0.0.1 or http://localhost (loopback) is allowed.
No production hostname, credentials, state-changing methods, or redirects.
Results are observations, not confirmed vulnerabilities.
"""
from __future__ import annotations

import argparse
import http.client
import json
from pathlib import Path
import re
from .safe_target import validate_fixture_origin, validate_fixture_path

MAX_SPEC = 100_000
SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./?=&%-]{0,250}$")  # deprecated: use validate_fixture_path
LEAK = re.compile(r"(?:Traceback \(most recent call last\)|node_modules/|at [A-Za-z0-9_.$]+ \([^)]*:\d+:\d+\)|SQL syntax error)", re.I)


def validate_base(base):
    return validate_fixture_origin(base)


def validate_spec(spec):
    if not isinstance(spec, dict) or set(spec) != {"endpoints"} or not isinstance(spec.get("endpoints"), list):
        raise ValueError("endpoints list required")
    if not 1 <= len(spec["endpoints"]) <= 50:
        raise ValueError("1 to 50 endpoint cases required")
    paths = set()
    for e in spec["endpoints"]:
        if not isinstance(e, dict) or set(e) != {"path", "access"} or e.get("access") not in ("protected", "public"):
            raise ValueError("endpoint access must be protected or public")
        path = e.get("path")
        validate_fixture_path(path)
        if path in paths:
            raise ValueError("duplicate path")
        paths.add(path)
    return spec["endpoints"]


def send(host, port, path, method, headers):
    conn = http.client.HTTPConnection(host, port, timeout=3)
    try:
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        # Read bounded bytes only; never persist response payload
        body = resp.read(8192).decode("utf-8", errors="replace")
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, bool(LEAK.search(body))
    finally:
        conn.close()


def audit(base, spec):
    host, port = validate_base(base)
    endpoints = validate_spec(spec)
    findings = []
    observations = []
    for item in endpoints:
        path = item["path"]
        try:
            status, headers, trace = send(host, port, path, "GET", {
                "Origin": "https://untrusted.invalid",
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Authorization": "Bearer nmsa-intentionally-invalid",
            })
        except (OSError, TimeoutError, http.client.HTTPException):
            observations.append({"path": path, "status": "UNREACHABLE"})
            continue
        observations.append({"path": path, "status": status})
        # A redirect may lead outside this test harness. Never follow it or
        # classify the contract as clean without inspecting route intent.
        if 300 <= status <= 399 or status >= 500:
            findings.append({"path": path, "id": "ambiguous-response",
                             "status": "INCOMPLETE", "observed_status": status,
                             "reason": "Redirect or server failure requires independent review"})
        if item["access"] == "protected" and status not in (401, 403):
            findings.append({"path": path, "id": "protected-route-auth-contract",
                             "status": "REVIEW", "observed_status": status,
                             "reason": "Invalid token did not produce 401/403; inspect auth policy"})
        cors = headers.get("access-control-allow-origin")
        if item["access"] == "protected" and cors in ("*", "https://untrusted.invalid"):
            findings.append({"path": path, "id": "protected-route-cors",
                             "status": "REVIEW", "reason": "Protected route allows untrusted origin"})
        if trace:
            findings.append({"path": path, "id": "error-information-disclosure",
                             "status": "REVIEW", "reason": "Server response resembles a stack trace"})
        if headers.get("access-control-allow-credentials", "").lower() == "true" and cors == "*":
            findings.append({"path": path, "id": "cors-wildcard-with-credentials",
                             "status": "REVIEW", "reason": "CORS wildcard and credentials conflict"})
    unreachable = (any(x["status"] == "UNREACHABLE" for x in observations)
                   or any(f.get("status") == "INCOMPLETE" for f in findings))
    return {"schema": "nmsa-api-contract-0.1", "verdict": "INCOMPLETE" if unreachable else "REVIEW" if findings else "OBSERVED_NO_FINDINGS",
            "observations": observations, "findings": findings,
            "note": "Loopback-only GET with intentionally invalid bearer token. No real authentication or authorization bypass testing. Never evidence of absence of vulnerabilities."}


def main(argv=None):
    p = argparse.ArgumentParser(description="Safe API contract probe of a local test server")
    p.add_argument("--base", required=True, help="http://127.0.0.1:PORT only")
    p.add_argument("--spec", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args(argv)
    src, dest = Path(args.spec).resolve(), Path(args.output).resolve()
    if not src.is_file() or src.stat().st_size > MAX_SPEC or not dest.parent.is_dir() or src == dest:
        p.error("Invalid spec/output")
    try:
        spec = json.loads(src.read_text(encoding="utf-8"))
        # validate origin and spec before any network access
        validate_base(args.base)
        validate_spec(spec)
        result = audit(args.base, spec)
    except (ValueError, TypeError, json.JSONDecodeError):
        p.error("Invalid or unsafe API test configuration")
    dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"verdict": result["verdict"], "findings": len(result["findings"])}))
    return 2 if result["verdict"] == "INCOMPLETE" else 1 if result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
