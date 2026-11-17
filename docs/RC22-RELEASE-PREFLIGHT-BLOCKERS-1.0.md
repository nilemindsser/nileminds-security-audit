# NMSA v1.0 RC22 — Candidate preflight: NOT READY

**Status: BLOCKED. No v1.0 production release tag is permitted.**

This is a conservative release-blocker matrix and code preflight, not
an independent audit or a sign-off on a stable security release.

## Baseline and evidence

The RC21 handoff was merged at `7d4be89`; independent security
review GitHub issue #26 remains open, with no independent reviewer
report on record at the time of preparation.

RC19: Docker Desktop remained available while the starting DeskMCP
shell lived, then became unavailable once that launcher shell exited.
The launcher-session persistence claim remains false.

RC20: Trivy DB updated on 2026-11-17; a **cached** local
`node:20-bookworm-slim` image had 7 CRITICAL, 72 HIGH, 145 MEDIUM,
96 LOW and 10 UNKNOWN vulnerability scanner signals. These findings
have not yet been independently triaged, so the image is **not**
accepted for a stable release. Metadata freshness is time-dependent.

RC21: review instructions prepared, but independent review NOT RUN.
RC17: signed-blob verification utility exists, but actual trusted
Docker image manifest signature and SBOM have NOT been independently
verified.

## Release gate amendment

The existing RC14 release gate explicitly tracked image provenance
but did not separately track critical/high vulnerability triage.
RC22 adds required `image_vulnerability_triage`, currently
`PENDING`, as an **independent mandatory blocker**.

Every release gate input remains self-reported historical evidence,
not live GitHub CI or cryptographic attestation. RC22 reports
`evidence_snapshot: HISTORICAL_NOT_LIVE` and
`source_ci_freshness_verified:false` even when all supplied
states claim PASS.

Any missing or malformed evidence field fails closed; even if all
fields are set to PASS, the assessment is merely
`REVIEW_REQUIRED`, not production authorization. Neither
`production_authorized` nor `external_skill_execution_authorized`
can be true as a result of this tool.

## Explicit remaining gates

1. **Docker launcher persistence:** BLOCKED.
2. **Trusted publisher, signed image-manifest and reviewed SBOM:**
   PENDING.
3. **Independent analysis and remediation of RC20 image
   vulnerability signals:** PENDING.
4. **Independent NMSA architecture/code review:** NOT RUN.
5. **Owner v1.0 release decision:** PENDING.

Before making a stable v1.0 tag, check the actual source SHA, complete
independent tests and review, verify up-to-date authenticated scanner
evidence on an approved immutable image, close all high-risk
findings, and obtain explicit owner release approval.

No production release, external third-party skill execution, or host
configuration changes are authorized by this preflight.

**RC22 PREFLIGHT GENERATED; V1.0 STABLE RELEASE BLOCKED.**
