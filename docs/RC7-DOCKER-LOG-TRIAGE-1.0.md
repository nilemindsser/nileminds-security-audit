# NMSA v1.0 RC7 — Read-only Docker diagnostic log triage

## Local evidence (2026-11-15)
Latest diagnostic confirmed `desktop-linux` Docker context with
stopped Desktop service and unavailable Linux daemon. Four allowlisted
Docker log files were read, with no raw log contents copied into reports.

Observed keyword-level indicators:
- WSL-related failure patterns: **9**
- Permission-related failure patterns: **2**
- Backend exit, named-pipe, and resource failure patterns: **0**

These counts are *not* root-cause proof. Log messages may contain noisy
repeated retries; false positives and false negatives are possible.
The root cause remains **UNCONFIRMED**.

## Scope of tool
`python -m nmsa.docker_log_triage` processes only the allowlisted
recent host/vm files beneath the local Docker logs directory, up to
2 MB each. It rejects symlinks and paths outside the selected folder.
The output includes only bounded named signal counts and coarse status;
it does not include log text, URLs, secrets, usernames, IP addresses,
local paths or machine identifiers.

The tool is read-only: no service restart, no Docker reset, no WSL
mutation, no image pulls, no container launch, no external agent skill
execution.

## Tests and release constraints
- Unit tests with Semgrep installed: **92 PASS**.
- Log triage report: **REVIEW**, not a failure-cause confirmation.
- Docker stability and the seven RC5 negative probes: still **BLOCKED**.
- Before claiming root cause, a human should review relevant localized
  error context privately, compare event timestamps to the engine
  shutdown, and decide a safe remediation without destructive resets.
- No production application or external repository modified.

**Gate: v1.0 RC7 CODE VERIFIED / DOCKER RUNTIME BLOCKED.**
