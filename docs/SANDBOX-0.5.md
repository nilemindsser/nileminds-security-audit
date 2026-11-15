# NMSA Sandbox Preview — v0.5 (fail closed)

## What is implemented

A **fixed, benign** Python fixture is available through `python -m nmsa.sandbox --run-fixture`.
It does **not** accept arbitrary commands, third-party skills, volumes or network
access, and it never automatically pulls container images.

The allowlisted Docker settings are:
- `--network none` (no container network interface)
- `--read-only` (read-only container filesystem)
- `--cap-drop ALL`
- `--security-opt no-new-privileges:true`
- `--user 65534:65534`
- `--pids-limit 32`, `--memory 128m`, `--cpus 0.5`
- `--tmpfs /tmp:rw,noexec,nosuid,size=8m,mode=1777`
- no project mount, host socket mount, credentials, privileged mode or host device access
- Python isolated mode `-I -S`

**Critical:** A container itself is not a verified security boundary against a
malicious host kernel, engine vulnerabilities or configuration mistakes.
Review and pin the container image digest before any real use. The version
tag in the preview is not immutable and no image signature is verified.

## Preconditions

1. Docker CLI and Linux Docker daemon must both be available.
2. The exact fixture image must already be present locally, provisioned
   and verified by a separate trusted process.
3. The test returns a known marker with exit code zero.

The fixture's known marker tests benign execution, NOT network-denial
enforcement or access-control bypass attempts. The actual negative security
tests are still pending.

## Tested outcomes

- Windows Docker CLI installed.
- Docker daemon initially unavailable (`linux_docker_daemon_required`).
- A Docker Desktop start request was issued, but readiness was not confirmed.
- Unit tests verify required restrictions, rejection of modified profile,
  rejection when Docker is absent, no source mounts or arbitrary payloads.
- None of the external Cloudflare/Security Audit Skills scripts has run.

## Status

**SANDBOX_PREVIEW — BLOCKED / NOT SECURITY-VALIDATED**

No execution adapter for third-party skills has been implemented. Existing
review and quarantine gates continue to apply.

## Next security acceptance criteria
- Verified and digest-pinned image; known base image provenance.
- Empirical tests denying outbound TCP, DNS, host-file access, secrets,
  host Docker socket, privilege elevation, and writes to mounted projects.
- OS-level sandbox runtime is independently reviewed.
- Negative test artifacts and test environment recorded with hashes.
- No external skill execution before explicit owner authorization.
