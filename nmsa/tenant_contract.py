"""Opt-in, GET-only tenant isolation probes against a controlled loopback fixture.

This does not prove that authorization is secure. No real tokens, live services,
arbitrary URLs, redirects, POST, PATCH, DELETE, or resource enumeration.
"""
from __future__ import annotations

import argparse
import http.client
import json
from pathlib import Path
from .api_contract import validate_base, SAFE_PATH

MAX_SPEC_BYTES = 100_000


def validate_cases(spec):
    cases = spec.get("cases") if isinstance(spec, dict) else None
    if not isinstance(cases, list) or not 1 <= len(cases) <= 30:
        raise ValueError("1-30 cases required")
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"path", "owner", "other"}:
            raise ValueError("Each case requires path, owner and other")
        path = case["path"]
        if not isinstance(path, str) or not SAFE_PATH.fullmatch(path) or path.startswith("//") or ".." in path:
            raise ValueError("Unsafe path")
        if case["owner"] not in ("A", "B") or case["other"] not in ("A", "B") or case["owner"] == case["other"]:
            raise ValueError("Distinct fixture identities A and B required")
    return cases


def get_status(host, port, path, identity):
    conn = http.client.HTTPConnection(host, port, timeout=3)
    try:
        # Fixture-only identities. Never read actual credentials or env tokens.
        conn.request("GET", path, headers={"Authorization": f"Bearer nmsa-fixture-{identity}",
                                            "Cache-Control": "no-store",
                                            "Accept": "application/json"})
        response = conn.getresponse()
        response.read(4096)
        return response.status
    finally:
        conn.close()


def audit_tenants(base, spec):
    host, port = validate_base(base)
    cases = validate_cases(spec)
    observations, findings = [], []
    for i, case in enumerate(cases):
        path = case["path"]
        statuses = {}
        for label, identity in (("owner", case["owner"]), ("other", case["other"])):
            try:
                statuses[label] = get_status(host, port, path, identity)
            except (OSError, TimeoutError, http.client.HTTPException):
                statuses[label] = None
        # Intentionally no paths or credentials in reported findings beyond
        # predeclared fixture route, and no response content.
        observations.append({"case": i, "path": path,
                             "owner_status": statuses["owner"],
                             "other_status": statuses["other"]})
        if statuses["owner"] is None or statuses["other"] is None:
            findings.append({"case": i, "type": "UNREACHABLE"})
        elif statuses["owner"] != 200:
            findings.append({"case": i, "type": "BASELINE_UNMET",
                             "reason": "Fixture resource owner did not receive 200"})
        elif statuses["other"] not in (403, 404):
            findings.append({"case": i, "type": "CROSS_TENANT_ACCESS_REVIEW",
                             "reason": "Other fixture identity did not receive 403/404"})
    incomplete = any(x["type"] in ("UNREACHABLE", "BASELINE_UNMET") for x in findings)
    return {"schema": "nmsa-tenant-contract-0.7", "status":
            "INCOMPLETE" if incomplete else "REVIEW" if findings else "OBSERVED_NO_FINDINGS",
            "observations": observations, "findings": findings,
            "execution_authorized": False,
            "limitations": "Fixture tokens A/B only; GET, loopback only. Does not prove tenant RLS, identity enforcement, or absence of IDOR."}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Loopback-only tenant fixture contract test")
    parser.add_argument("--base", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    src, out = Path(args.spec).resolve(), Path(args.output).resolve()
    if not src.is_file() or src.stat().st_size > MAX_SPEC_BYTES or not out.parent.is_dir() or src == out:
        parser.error("Invalid input/output path")
    try:
        validate_base(args.base)
        spec = json.loads(src.read_text(encoding="utf-8"))
        validate_cases(spec)
    except (ValueError, TypeError):
        parser.error("Invalid or unsafe test specification")
    result = audit_tenants(args.base, spec)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "findings": len(result["findings"])}))
    return 2 if result["status"] == "INCOMPLETE" else 1 if result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
