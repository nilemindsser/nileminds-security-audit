# NMSA v1.0 RC6 — Docker/WSL read-only diagnostics

## Purpose

The Docker Desktop Linux daemon has repeatedly responded immediately
after launching Desktop and then disappeared at the next readiness check.
The diagnostic must not overstate a transient connection as sandbox
readiness, and must not change Docker, Windows, services, WSL, or registry.

## Implementation

Use `python -m nmsa.docker_diagnostics` to collect only these bounded
signals on Windows:

- Docker CLI context: `desktop-linux`, `default`, or `UNKNOWN`
- Docker Linux daemon responding: boolean
- Docker Desktop Windows service status: known status or `UNKNOWN`
- WSL query succeeded: boolean

Raw console output, paths, usernames, distribution names, errors,
environment variables and host secrets are **never copied** into the report.
All commands are fixed and read-only, with subprocess time limits and
`shell=False`. The diagnostic does not attempt service start, daemon
restart, image pulling, container execution, or external skill activation.

## Interpretation

- `BLOCKED`: Linux engine not responding
- `REVIEW`: Linux engine responding but unexpected Docker context
- `LIVENESS_ONLY`: one response confirms liveness, not sustained stability

All outputs contain `isolation_verified:false` and
`container_executed:false`. Only the separate RC4
`python -m nmsa.runtime_gate` can verify repeated engine responsiveness.
Even the repeated gate does not prove container isolation.

## Observed Windows state (2026-11-15)

```json
{
  "status": "BLOCKED",
  "reason": "linux_docker_engine_unavailable",
  "signals": {
    "docker_context": "desktop-linux",
    "docker_service": "Stopped",
    "linux_engine_available": false,
    "wsl_query_available": true
  },
  "isolation_verified": false,
  "container_executed": false
}
```

This does not establish why Docker Desktop has exited. Investigating its
crash logs, Windows event logs, virtualization settings, WSL errors or
service-start permissions is a separate, read-only diagnosis step.

## Approval gates still missing

- Stabilize Linux daemon on Windows and pass sustained checks
- Independently source and pin a trusted local image
- Run RC5 negative probes in an actual container
- Independent security review and assessment of any external skills

No production application or external skill has been executed.
