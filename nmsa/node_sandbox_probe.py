"""Opt-in fixed Node fixture for existing locally cached Docker images.

Never runs external skills; never pulls images, mounts host paths or
passes user-provided code. Intended for approved disposable local tests.
"""
from __future__ import annotations
import argparse
import json
import os
import subprocess
from .sandbox import DIGEST_RE, docker_command, FIXTURE
from .runtime_gate import verify

PROBE_JS = r"""
const fs=require('fs'),net=require('net');
const checks={};
checks.non_root=process.getuid()!==0;
try{fs.writeFileSync('/nmsa-rc11-root-probe','x');checks.root_read_only=false}
catch(e){checks.root_read_only=true}
checks.host_path_absent=!fs.existsSync('/nmsa-host-fixture');
checks.no_obvious_secret_env=!Object.keys(process.env).some(
k=>/(TOKEN|SECRET|PASSWORD|API_KEY)/i.test(k));
try{fs.writeFileSync('/tmp/nmsa-rc11-probe','ok');checks.limited_tmp_writable=true}
catch(e){checks.limited_tmp_writable=false}
try{const cap=fs.readFileSync('/proc/self/status','utf8').match(/^CapEff:\s*([0-9a-f]+)/mi);
checks.capabilities_dropped=!!cap&&BigInt('0x'+cap[1])===0n}
catch(e){checks.capabilities_dropped=false}
const sock=net.createConnection({host:'1.1.1.1',port:443});
let finished=false;
function done(blocked){if(finished)return;finished=true;checks.outbound_blocked=blocked;
sock.destroy();process.stdout.write(JSON.stringify(checks)+'\n')}
sock.on('connect',()=>done(false));
sock.on('error',()=>done(true));
sock.setTimeout(700,()=>done(true));
"""
EXPECTED = frozenset({"non_root", "root_read_only", "host_path_absent",
 "no_obvious_secret_env", "limited_tmp_writable",
 "capabilities_dropped", "outbound_blocked"})


def command(image_id):
    cmd = docker_command(image_id=image_id)
    assert cmd[-5:] == ["python", "-I", "-S", "-c", FIXTURE]
    return cmd[:-5] + ["node", "-e", PROBE_JS]


def evaluate(output):
    try:
        record = json.loads(output)
    except (ValueError, TypeError):
        return {"status": "FAIL", "reason": "malformed_response",
                "isolation_verified": False}
    if not isinstance(record, dict) or set(record) != EXPECTED or any(
        type(value) is not bool for value in record.values()
    ):
        return {"status": "FAIL", "reason": "unexpected_schema",
                "isolation_verified": False}
    failed = sorted(key for key, value in record.items() if not value)
    return {"status": "NEGATIVE_PROBES_PASS" if not failed else "FAIL",
            "failed_checks": failed, "passed_checks": 7-len(failed),
            "total_checks": 7, "isolation_verified": False,
            "note": "Limited behavioral observations; not container security certification"}


def run():
    image_id = os.environ.get("NMSA_SANDBOX_IMAGE_ID", "")
    if not DIGEST_RE.fullmatch(image_id):
        return {"status": "BLOCKED", "reason": "immutable_local_image_id_required",
                "isolation_verified": False}
    if verify(samples=3, delay=1)["status"] != "STABLE_FOR_FIXTURE_PRECHECK":
        return {"status": "BLOCKED", "reason": "unstable_linux_daemon",
                "isolation_verified": False}
    try:
        inspected = subprocess.run(
            ["docker","image","inspect",image_id,"--format","{{.Id}}"],
            capture_output=True,text=True,encoding="utf-8",errors="replace",
            timeout=10,shell=False)
        if inspected.returncode != 0 or inspected.stdout.strip() != image_id:
            return {"status": "BLOCKED", "reason": "image_id_not_preloaded_or_mismatch",
                    "isolation_verified": False}
        result = subprocess.run(command(image_id),capture_output=True,text=True,
                encoding="utf-8",errors="replace",timeout=45,shell=False)
    except (OSError,subprocess.TimeoutExpired):
        return {"status": "BLOCKED", "reason": "sandbox_runtime_failed",
                "isolation_verified": False}
    if result.returncode != 0:
        return {"status": "FAIL", "reason": "fixture_exit_nonzero",
                "isolation_verified": False}
    return evaluate(result.stdout)


def main(argv=None):
    p=argparse.ArgumentParser(description="Fixed local Docker Node negative probes")
    p.add_argument("--run", action="store_true", help="Explicitly execute benign probes")
    args=p.parse_args(argv)
    report = run() if args.run else {
        "status": "NOT_RUN", "reason": "explicit_run_flag_required",
        "isolation_verified": False}
    print(json.dumps(report,sort_keys=True))
    return 0 if report["status"]=="NEGATIVE_PROBES_PASS" else 2


if __name__=="__main__":
    raise SystemExit(main())
