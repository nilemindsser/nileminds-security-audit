# NMSA v1.0 RC11 — Disposable Node sandbox behavioral evidence

## Observed locally on Windows (2026-11-15)

- Before starting Docker Desktop, `docker desktop status` reported it
  was not running, and the Linux Engine endpoint was unavailable.
- Starting Docker Desktop and running the repeated readiness gate within
  **one controlled desktop process session** returned 3/3 successful
  Linux Engine responses.
- After that process session ended, a separate invocation could not
  connect to Docker Engine and the Docker Desktop processes were absent.
- The same-session test was repeated with an already installed
  `node:20-bookworm-slim` image, locally inspected by its immutable
  SHA256 image ID, and launched with `--pull never`.
- The real container returned **7/7 negative restriction probes PASS**.
  A repeated post-run engine gate also returned 3/3 successful samples.
- No additional image was fetched, no host mount attached, and no
  third-party skills, production workloads or user applications executed.

This suggests the remote desktop process/session lifecycle may terminate
the Docker Desktop child processes after the invoking shell exits. It
is a **strong hypothesis, not a confirmed platform root cause**.
No permanent service configuration change or destructive reset was made.

## Seven real behavioral probes

1. Non-root process identity
2. Read-only container root filesystem
3. Failed direct external TCP connection under `--network none`
4. No artificial host path mount
5. No obvious secret-named environment variables
6. Writable bounded tmpfs
7. Zero effective Linux capabilities

The harness uses fixed inline Node.js test code and the same restricted
Docker flags as the Python fixture. An explicitly set local SHA256
image ID and three stable daemon responses are mandatory. Only
`python -m nmsa.node_sandbox_probe --run` actually launches a fixture.

## Limitations and critical release gate

- Seven checks are limited behavioral evidence, **not** proof of complete
  isolation, protection from kernel escape, image integrity, supply
  chain security or safe execution of arbitrary third-party code.
- The preloaded Node image is not independently signed or audited as
  part of this run, and these checks do not authorize external skills.
- The Docker engine is not demonstrated stable **across** process
  sessions; automatic use by an independent agent remains blocked.
- Node negative probes are a **separate** implementation from RC5's
  Python-based fixed fixture. Passing Node does not imply RC5's
  Python-specific tests executed.
- Tests do not cover every network namespace, DNS, mount, secret
  injection, resource exhaustion or host kernel escape scenario.
- No production release approval has been granted.

## Local verification

- Local Python suite including the new Node fixture tests: **120 PASS**
  with Semgrep installed.
- Real Linux container: **7/7 behavioral checks PASS**.
- Docker daemon same-session liveness: **3/3 PASS** before and after.
- Engine availability between independently terminated desktop
  sessions: **FAIL** in follow-up check.

**RC11: LOCAL BEHAVIORAL VALIDATION ACHIEVED / INDEPENDENT RUNTIME
STABILITY AND PRODUCTION APPROVAL PENDING.**
