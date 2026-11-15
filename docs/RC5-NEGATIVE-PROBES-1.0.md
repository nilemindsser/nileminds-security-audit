# NMSA v1.0 RC5 — Fixed behavioral sandbox probes

## 2026-11-15 runtime evidence

Docker Desktop startup briefly returned Linux Engine 29.9.2, then the
`dockerDesktopLinuxEngine` pipe became unavailable. RC4's three-sample
stability gate subsequently returned BLOCKED at sample zero. No container
was started and no image was inspected or pulled during RC5.

## Implementation

The new `nmsa.sandbox_probes` module contains **fixed, reviewed-by-source**
synthetic Python code, not commands supplied by users, agents or downloaded
skills. It inherits RC3's explicit local image SHA256 ID requirement and
locked-down Docker command, and RC4's repeated Linux-engine readiness gate.

If and only if all prerequisites pass, the probe verifies:
1. The process is not root.
2. Writing to the container's root filesystem is denied.
3. A direct outbound TCP attempt fails.
4. An artificial `/nmsa-host-fixture` path is absent (no host mount).
5. Obvious secret-like environment variable names are absent.
6. The limited `/tmp` filesystem is writable.
7. Effective Linux capabilities are zero.

It does not mount any host files, use real secrets, access production,
run untrusted source, or auto-pull an image. It reports only boolean
outcomes, pass count and failed-check identifiers. Malformed probe
responses fail closed.

### Run only after independent review and preloading of an immutable image

```powershell
python -m nmsa.runtime_gate --samples 3 --delay 2
$env:NMSA_SANDBOX_IMAGE_ID = "sha256:<locally-reviewed-image-id>"
python -m nmsa.sandbox_probes
```

The digest placeholder is not an executable ID. The run must use a
separately reviewed, locally installed image. Inspecting an image ID
does not prove provenance, signing, freshness, or absence of malware.

## Interpret carefully

Even if all seven checks eventually pass, this is limited defense-in-depth
evidence, **not security certification**. It cannot prove:
- resistance to container/WSL kernel vulnerabilities or escape paths
- DNS and proxy behavior under all configurations
- no external host mounts via inherited/container runtime behavior
- secure image provenance or prevention of every secret exposure
- safe execution of quarantined third-party skills

The result always retains `isolation_verified:false`, pending independent
review and a broader audited sandbox test campaign.

## Local verification

- Python unit suite with locally installed Semgrep: **79 tests PASS**
- RC5 runtime: **BLOCKED — daemon_unavailable**
- Third-party AI skills: **NOT EXECUTED**
- NileMenu and other projects: **NOT MODIFIED**

**Release gate: RC5 CANDIDATE, runtime evidence incomplete.**
