# NMSA v1.0 RC10 — WSL vs Docker backend differential

## Verified real observations (2026-11-15)

- `wsl --version` returned WSL 2.6.3, kernel 6.6.87.2.
- `wsl -d Ubuntu --exec /bin/uname -s`: Linux, exit 0.
- `wsl -d docker-desktop --exec /bin/uname -s`: Linux, exit 0.
- `docker info`: Linux engine unreachable.
- `docker desktop status`: reported Docker Desktop was not running.
- Windows `com.docker.service`: Stopped, Manual.
- Windows `HypervisorPresent`: True.

This strongly narrows the incident from a general WSL outage to the
Docker Desktop application/backend and/or its engine availability at
the observed moment. However the reason for Docker Desktop exiting
is **unconfirmed**. A stopped Manual service is not independently proof
of misconfiguration.

The `Win32_Processor.VirtualizationFirmwareEnabled` and SLAT fields
were False while a WSL2 distro could execute Linux commands. Do not
interpret these processor fields alone as proof that virtualization
was disabled.

## What changed

`python -m nmsa.wsl_engine_probe` executes three fixed, bounded
read-only checks: Ubuntu WSL Linux uname, Docker Desktop WSL Linux
uname and Docker Linux Engine info. It returns strictly booleans and
approved next-action labels; stdout, stderr, user data, credentials and
machine identifiers are discarded.

It can briefly start a pre-existing WSL distribution; it does not
mutate configuration, reset Docker, install/update packages, download
images, run a container or activate external AI skills.

A successful WSL command does not prove Docker Engine stability.
A successful single Docker response remains `LIVENESS_ONLY`, never
an isolation/security certification.

## Verification and remaining gates

- Local unit suite: **112 PASS**, Semgrep available.
- Runtime differential: `DOCKER_BACKEND_REVIEW`.
- Root cause: **UNCONFIRMED**.
- Sandbox real negative probes: **NOT RUN** (engine unavailable).
- Next safe investigation: Docker Desktop/backend lifecycle and
  time-correlated local error context, requiring no destructive reset.
- No other application repositories modified.

**Release gate: RC10 SOFTWARE VERIFIED / ISOLATION NOT APPROVED.**
