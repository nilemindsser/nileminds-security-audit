# NMSA v1.0 RC12 — Cross-process Docker liveness gate

## Measured on Windows, 2026-11-15

The Docker Desktop process was initially absent. The following
sequential experiments were conducted on the authorized Windows desktop
through DeskMCP.

1. A single desktop terminal launched `docker desktop start --detach
   --timeout 20`. The repeated Docker Linux readiness gate returned
   **3/3 PASS** and the process showed running Docker backend/desktop
   processes.
2. A separate terminal invocation checked readiness and received
   **0/3, BLOCKED**. `docker desktop status` reported Desktop not
   running. Thus the native CLI `--detach` option alone does not
   preserve Docker Desktop beyond the remote execution session.
3. The fixed two-phase RC12 gate was executed:
   - Phase capture: `CAPTURED`, `ready:true`.
   - Phase confirm in another desktop process: `BLOCKED`,
     `daemon_unavailable_after_session_boundary`.
   - The confirm command also reported Desktop not running.

These observations strongly support a process-session lifetime or
desktop execution-environment issue, **but do not identify which
Desktop/DeskMCP/OS mechanism terminates the processes**. No reboot,
reset, service configuration change or installation was performed.

## New optional gate

```powershell
python -m nmsa.cross_session_gate --capture D:\NileMinds\nmsa-rc12-cross-session-probe.json
# The original shell must actually exit; run the next command in a NEW shell
python -m nmsa.cross_session_gate --confirm D:\NileMinds\nmsa-rc12-cross-session-probe.json
```

The marker is strictly local, created with exclusive creation to avoid
overwriting files; it is not a credential, signature or tamper-proof
security attestation. A marker must be less than ten minutes old,
schema-valid, and from a different process ID. Both phases independently
require three successful Docker Linux readiness responses. The
confirm phase always fails closed if the previous capture failed,
the engine stopped, timestamps are invalid, the file is corrupt, or
the same process attempts both stages. No Docker images or containers
are executed by this gate.

## Correct status labels

- `CAPTURED`: phase-one liveness only, **not** cross-session validation.
- `CROSS_PROCESS_LIVENESS_PASS`: daemon responded from different
  processes, **not** independent security isolation proof; process-ID
  reuse or modified local markers may invalidate the inference.
- `BLOCKED`: never approve a remote multi-session sandbox workflow.

The seven RC11 negative behavioral probes passed in one live container
in a previous session, not this cross-session trial.

## Remaining owner-level decisions

- Diagnose DeskMCP child-process teardown / Docker Desktop app lifetime
  via authorized platform logs and runtime documentation before
  attempting persistent background execution.
- Independently review local image provenance and container restrictions.
- Separate process liveness from sandbox isolation: neither
  automatically authorizes untrusted skills or production activity.
- No other project repository or production environment was altered.

**RC12 CROSS-SESSION LIVENESS: BLOCKED / SOFTWARE IMPLEMENTED.**
