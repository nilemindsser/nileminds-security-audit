# NMSA v1.0 RC4 — Docker runtime liveness gate

## Real Windows observation — 2026-11-15

Initial Docker Desktop startup returned a Linux engine response:
`linux 29.9.2`. A separate immediate subsequent attempt returned a
missing `dockerDesktopLinuxEngine` named pipe error. Later
`wsl -l -v` showed Docker Desktop and other WSL distros stopped,
and the `com.docker.service` was stopped. This is an intermittent
startup, **not evidence that the Docker runtime is reliably usable**.

The RC4 gate measured three intended Linux daemon liveness samples,
and stopped at the first failure:
`BLOCKED`, `passed_samples:0`, `required_samples:3`,
`isolation_verified:false`.

## Implemented

- `python -m nmsa.runtime_gate --samples 3 --delay 2` checks for
  three separate Linux Docker responses with a bounded interval.
  The default does not start Docker Desktop, pull images, or launch
  a container.
- The fixed, benign `nmsa.sandbox --run-fixture` now additionally
  requires three successful runtime liveness samples (1s apart).
  If any sample fails, it returns `docker_daemon_not_stable` and
  does not inspect images or launch a container.
- Invalid sample count, excessive delays, CLI absence, failed daemon
  probes and Linux/Windows daemon mismatches fail closed.
- Reports explicitly contain `isolation_verified:false` even if the
  runtime appears stable. Liveness is not a security boundary.

## Tests

Six new regression tests simulate multiple successes, an engine that
drops after one success, a blocked container launch after unstable
readiness, missing CLI, and malformed configuration.

## Remaining release blockers

- Docker Desktop / WSL Linux daemon must remain connected reliably.
- An independently reviewed image must be preloaded and pinned by its
  local immutable SHA256 ID; no automatic pull.
- Execute real **negative** fixture tests for network/DNS, host
  mounts, secrets, privilege escalation, process and memory limits.
- Review Docker Desktop / WSL settings and non-default privileges.
- Existing checks still do not prove the real sandbox can resist
  malicious executable skills.
- Third-party AI skills remain quarantined and no private application
  code or production endpoint is involved in these tests.

**Status: RC4 SOFTWARE VERIFIED / RUNTIME BLOCKED / NOT APPROVED.**
