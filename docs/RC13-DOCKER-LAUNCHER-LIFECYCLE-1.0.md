# NMSA v1.0 RC13 — Launcher lifecycle and cross-process semantics

## Controlled Windows observation — 2026-11-15

Docker Desktop was initially stopped. Tests were performed **without**
installing new software, resetting Docker/WSL, changing Windows services,
running untrusted skills or touching other project repositories.

The experiment isolated the parent launcher process duration:

| Stage | Observation |
|---|---|
| A. Launch Docker Desktop using `docker desktop start --detach` inside a DeskMCP-managed PowerShell session, then keep that session open | Linux daemon passed three successive readiness probes |
| B. From a separate DeskMCP PowerShell invocation while the launcher session was still alive | Three Linux daemon probes passed; Docker Desktop status was running |
| C. After the launcher PowerShell printed its ending marker and finished | From a new DeskMCP invocation, first readiness probe failed; Desktop was no longer running |

This is evidence of strong **association** between the initiating process
lifetime and Docker Desktop lifetime in this particular DeskMCP setup.
It is not yet proof of the exact mechanism: a desktop session isolation
policy, launcher-owned process tree cleanup, job object, or other OS
behavior. The existing `--detach` option did **not** persist Desktop
beyond the parent shell termination.

## Security correction in RC13

The previous RC12 confirm phase could return
`CROSS_PROCESS_LIVENESS_PASS` because two Python processes had different
PIDs even if the original PowerShell launcher was still running.
That did not demonstrate *cross-launcher-session* persistence.

RC13 replaces that misleading state with
`CROSS_PROCESS_LIVENESS_ONLY`. For such an observation it reports
`cross_process_verified:true`, `cross_session_verified:false`,
`launcher_exit_verified:false` and `isolation_verified:false`.
Actual daemon failure remains `BLOCKED`.

This is a conservative labeling repair; it does not claim to solve
DeskMCP lifecycle management or to authorize background execution.

## Local test plan and results

- Python suite with pinned local Semgrep enabled: 127 tests expected,
  including a regression proving two OS processes are not sufficient
  evidence of distinct launcher-session survival.
- Real lifecycle experiment: same-launcher **PASS**; independent
  process while launcher alive **PASS**; after launcher ends **BLOCKED**.
- The RC11 fixed Node.js container restriction fixture previously
  passed 7/7, but was not rerun in this RC13 experiment.
- Independent runtime persistence remains **BLOCKED** and production
  security approval remains **NOT APPROVED**.

## Next safe operational decision

Use a separately authorized process owner/service mechanism when
cross-session persistence is required. Do not implement a Windows
scheduled task, automatic startup, admin service, SYSTEM process,
process-detachment workaround, or host configuration change until the
owner explicitly approves its scope and lifecycle controls. Any
subsequent solution must be tested from independent terminated launcher
sessions and retain sandbox restrictions.
