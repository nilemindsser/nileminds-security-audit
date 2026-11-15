"""Fixed negative Docker sandbox probes. Never executes third-party source.

Tests only a synthetic container built from a separately reviewed, preloaded,
immutable image ID. This is not a container escape test or a security guarantee.
"""
from __future__ import annotations
import json
import os
import subprocess
from . import sandbox
from .runtime_gate import verify as verify_runtime

# This string is fixed in this source file; CLI cannot accept code, paths or URLs.
PROBE = """import json,os,socket
checks={}
checks["non_root"]=os.geteuid()!=0
try:
    open("/nmsa-root-write-probe","w").write("fixture")
    checks["root_read_only"]=False
except OSError:
    checks["root_read_only"]=True
try:
    s=socket.socket()
    s.settimeout(0.4)
    s.connect(("1.1.1.1",443))
    checks["outbound_blocked"]=False
except OSError:
    checks["outbound_blocked"]=True
finally:
    s.close()
checks["host_path_absent"]=not os.path.exists("/nmsa-host-fixture")
checks["no_obvious_secret_env"]=not any(
    any(word in key.upper() for word in ("TOKEN","SECRET","PASSWORD","API_KEY"))
    for key in os.environ)
try:
    with open("/tmp/nmsa-fixture","w") as f: f.write("ok")
    checks["limited_tmp_writable"]=True
except OSError:
    checks["limited_tmp_writable"]=False
try:
    with open("/proc/self/status") as f:
        caps=next((x.split(":",1)[1].strip() for x in f if x.startswith("CapEff:")),None)
    checks["capabilities_dropped"]=(caps is not None and int(caps,16)==0)
except (OSError,ValueError):
    checks["capabilities_dropped"]=False
print(json.dumps(checks,sort_keys=True))
"""
EXPECTED = frozenset({
    "non_root", "root_read_only", "outbound_blocked", "host_path_absent",
    "no_obvious_secret_env", "limited_tmp_writable", "capabilities_dropped",
})


def inspect_result(output):
    try:
        record = json.loads(output)
    except (ValueError, TypeError):
        return {"status": "FAIL", "reason": "invalid_probe_output", "isolation_verified": False}
    if (not isinstance(record, dict) or set(record) != EXPECTED
            or any(type(v) is not bool for v in record.values())):
        return {"status": "FAIL", "reason": "unexpected_probe_schema", "isolation_verified": False}
    failed = sorted(k for k, v in record.items() if not v)
    return {
        "status": "FAIL" if failed else "NEGATIVE_PROBES_PASS",
        "failed_checks": failed, "passed_checks": len(EXPECTED) - len(failed),
        "total_checks": len(EXPECTED), "isolation_verified": False,
        "note": "Limited behavioral probes, not proof of container escape resistance",
    }


def run_probes():
    if sandbox.readiness()["status"] != "READY_FOR_FIXTURE":
        return {"status": "BLOCKED", "reason": "daemon_unavailable", "isolation_verified": False}
    if verify_runtime(samples=3, delay=1)["status"] != "STABLE_FOR_FIXTURE_PRECHECK":
        return {"status": "BLOCKED", "reason": "unstable_daemon", "isolation_verified": False}
    image_id = os.environ.get("NMSA_SANDBOX_IMAGE_ID", "")
    if not sandbox.DIGEST_RE.fullmatch(image_id):
        return {"status": "BLOCKED", "reason": "immutable_image_id_required", "isolation_verified": False}
    try:
        checked = subprocess.run(
            ["docker", "image", "inspect", image_id, "--format", "{{.Id}}"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=10, shell=False)
        if checked.returncode != 0 or checked.stdout.strip() != image_id:
            return {"status": "BLOCKED", "reason": "local_image_id_mismatch", "isolation_verified": False}
        cmd = sandbox.docker_command(image_id=image_id)
        assert cmd[-1] == sandbox.FIXTURE
        cmd[-1] = PROBE  # No variable/user-supplied code.
        completed = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=45, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "BLOCKED", "reason": "probe_runtime_failure", "isolation_verified": False}
    if completed.returncode != 0:
        return {"status": "FAIL", "reason": "probe_nonzero_exit", "isolation_verified": False}
    return inspect_result(completed.stdout)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Fixed synthetic Docker restriction probes")
    parser.parse_args(argv)
    report = run_probes()
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "NEGATIVE_PROBES_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
