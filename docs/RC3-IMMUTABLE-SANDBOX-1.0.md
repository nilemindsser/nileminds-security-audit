# NMSA v1.0 RC3 — immutable local sandbox image policy

## Change

The optional **benign fixture-only** Docker runner now fails closed unless
an explicit local image ID of the form `sha256:<64 lowercase hex>` is provided
via `NMSA_SANDBOX_IMAGE_ID`.

Previously it selected a mutable `python:3.12.9-alpine3.21` image tag.
A tag may point to different image content over time, so it cannot serve as
an immutable assurance. The new runner checks `docker image inspect` on the
literal image ID, rejects any mismatch, then invokes `docker run --pull never`
with the verified local ID rather than a tag.

No image auto-pull is performed and no third-party skill is executed.
User-selected local image ID alone is **not provenance or signature
verification**. The image must be separately reviewed, acquired through a
trusted process, and its ID recorded with verification evidence.

### Explicit usage (only once Docker Linux daemon is operational)

```powershell
docker image inspect <trusted-preloaded-image> --format "{{.Id}}"
$env:NMSA_SANDBOX_IMAGE_ID = "sha256:<64-character-reviewed-image-id>"
python -m nmsa.sandbox
python -m nmsa.sandbox --run-fixture
```

Never copy the example placeholder as an actual ID. The ID must correspond
to a locally installed image; inspect does not authorize it or certify safety.

## Fixed controls

- No arbitrary script or external skills supported by fixture runner.
- No host directory, Docker socket, or external secrets mounted.
- `--network none`, `--read-only`, capability drop, non-root, pids,
  memory and CPU ceilings, no-new-privileges and limited tmpfs.
- CLI uses `--pull never` to prevent incidental external image fetches.
- Missing daemon, malformed IDs, missing image and mismatched ID block execution.

## Verification state

The Docker daemon was not available on this Windows desktop at the
start of RC3. Structural unit tests and mocked failure-path tests
verify argument construction and fail-closed decisions, **not** actual
network isolation or host file protection.

### Must still be done before any external skill execution
- Independently review/pin base-image provenance and signature.
- Empirically confirm restrictions within an isolated, trusted runner.
- Run negative probes for network/DNS, host-file access, privileges and secrets.
- Review platform-specific Docker/WSL escape risk.
- Complete human triage of quarantined third-party skills.
- Obtain owner approval for a separately designed activation adapter.

**Gate: BLOCKED — not production-approved.**
