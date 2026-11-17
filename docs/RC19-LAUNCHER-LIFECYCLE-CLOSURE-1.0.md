# NMSA RC19 — Docker launcher lifetime: controlled retest and operational stop

## Goal and current outcome

Owner-approved security-closure work, not feature expansion. RC19
investigates the Docker Desktop launcher lifecycle via DeskMCP and
prevents cross-process liveness being mistaken for readiness after the
original launching session has terminated.

**Operational outcome: BLOCKED.** No safe, demonstrated mechanism to
preserve Docker Desktop after the DeskMCP launcher exits was established.
This is a documented environmental dependency, not a resolved problem.

## November 17, 2026 — observed controlled test on authorized Windows host

1. Initial shell reported Docker Desktop not running. Fixed Linux
   daemon gate returned **0/3, BLOCKED**.
2. From a DeskMCP-owned PowerShell process, `docker desktop start
   --detach --timeout 20` returned success. The fixed repeated
   daemon gate responded **3/3, PASS**.
3. From another distinct DeskMCP command while the launching process
   was still alive, Linux daemon gate again returned **3/3, PASS**.
   The OS reported **seven** Docker Desktop/backend processes.
4. Read-only Win32_Process enumeration reported Docker Desktop and
   backend processes with parent-process identifiers. A displayed
   desktop executable was parented to a process that was no longer
   visible when queried; this does not prove an OS job-object cleanup
   mechanism, crash, session kill policy or root cause.
5. After the launch-holding shell completed, the fixed gate from a
   fresh DeskMCP command returned **0/3, BLOCKED**.

The repeatability strengthens the **association** with launcher
session lifetime. The mechanism remains **UNCONFIRMED**.
No host service, scheduled task, registry setting, startup entry,
Docker daemon configuration, WSL distribution or remote project
configuration was changed.

## RC19 code correction

The RC13 gate already reports a separate-process response as
`CROSS_PROCESS_LIVENESS_ONLY`, with
`cross_session_verified:false` and
`launcher_exit_verified:false`. However, its command line still
returned exit status **0** on this result. A shell/CI consumer could
mistake that status for successful cross-session verification.

RC19 corrects the exit code to **2** for the non-authorizing
`CROSS_PROCESS_LIVENESS_ONLY` result. Capture phase still returns 0
for `CAPTURED` (the first diagnostic step only); `BLOCKED` returns
2. Tests enforce the semantics and preserve the RC14 production gate's
`launcher_exit_persistence` blocker.

## Operational response

- Do not extend Docker Desktop lifetime via scheduled tasks, services,
  privilege escalation, detached process hacks or config changes
  without a separate owner-approved host operations change and
  rollback plan.
- For short, explicitly authorized fixed benign tests, Docker may be
  started within an owned session and shut down by session lifecycle;
  this is **not** evidence of safe autonomous persistence.
- Independently investigate DeskMCP's process-tree ownership, Windows
  process/job isolation and Docker Desktop event records using
  read-only authorized diagnostics.
- Demonstrate fresh launcher-exit checks and independent verifier
  evidence before changing the release assurance gate.
- Release, third-party skills and production execution remain blocked.

**RC19: SCANNER INTEGRITY FIX DELIVERED / DOCKER LIFETIME UNRESOLVED.**
