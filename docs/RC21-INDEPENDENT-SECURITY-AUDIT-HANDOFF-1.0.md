# NMSA RC21 — Independent Security Review Handoff

**Review status: NOT STARTED / AWAITING INDEPENDENT REVIEWER.**

This is a ready-to-use assessment specification, not a review finding
or authorization. A reviewer **other than the NMSA implementation agent**
must examine the pinned NMSA commit, independently reproduce important
evidence, and produce an attributable, dated report.

## Scope

Repository: `https://github.com/nilemindsser/nileminds-security-audit`.
Baseline at handoff: RC20 main commit `87565b4`. Review this SHA or
record a new SHA and explicitly note differences. Do not silently
assume current `main` corresponds to the baseline.

Read-only or non-production test scope only:
- Scanner orchestration, CLI subprocess arguments, file writes, secret
  redaction and error/timeout handling
- Semgrep and Gitleaks schema acceptance, incomplete scanner handling,
  rule coverage and false positives
- Loopback-only fixtures and target URL validation
- Third-party skill inventory and prompt injection triage: **do not run
  real third-party skills or import their code**
- Cross-process vs cross-launcher Docker readiness, exact exit codes,
  Docker sandbox controls and limits of fixed negative probes
- Vulnerability DB refresh policy, stale DB bypass risks, image
  identity/provenance and Trivy result parsing
- Sigstore signed-blob checks, expected identity, trust roots, absence
  of Docker image-manifest binding and missing SBOM verification
- Release assurance gate: production must remain **not authorized**

## Required independent verification

1. Verify Git SHA/branch and capture exact tool versions used.
2. Run complete Python test suite; record pass/fail/skip counts.
3. Run repository Semgrep rule validation and synthetic benchmark.
4. Run Gitleaks on the checked-out repository, without exposing raw
   candidate secrets. Adjudicate the existing 40-hex-character
   Cloudflare snapshot reference as true positive/false positive
   with evidence; do not suppress solely by pattern.
5. Test malformed scanner outputs, stale Trivy metadata, timeouts,
   no-results situations, and secret redaction with synthetic inputs.
6. Verify `nmsa.cross_session_gate --confirm` returns **nonzero**
   when only distinct process PIDs are demonstrated.
7. Examine Docker process parent/launcher lifetime evidence without
   changing host services or creating persistent tasks. Do not claim
   containment proof from seven limited probes.
8. Confirm the cached Node fixture image's observed RC20 results:
   **7 CRITICAL, 72 HIGH, 145 MEDIUM, 96 LOW, 10 UNKNOWN** as
   historical observations from the 2026-11-17 Trivy scan. A
   new scan must record a fresh DB timestamp and image ID; do not
   assert the same counts apply to changed images or databases.
9. Review image provenance policy, SBOM requirements and signed
   Docker manifest binding. Signed arbitrary blobs do not qualify.
10. Provide exploitability/impact assessment and reproducible steps
    for all material issues using only safe, owned fixtures.

## Report structure (mandatory)

- Reviewer identity and separation from implementation work
- Date, pinned SHA, machine/test environment and tool versions
- Scope/limitations, whether Docker actually persisted after launcher exit
- Findings by ID, severity, evidence, affected files, exploit scenario,
  reproduction method, confidence, and remediation recommendation
- Open blocker matrix and accepted risks with named approval references
- Evidence artifacts or trustworthy checksums, without secrets or
  host-private identifiers
- Final reviewer determination: **PASS / FAIL / INCONCLUSIVE**.
  A pass is not final owner production approval.

## Existing evidence references

- RC18: `docs/RC18-SECURITY-INTEGRATION-REVIEW-1.0.md`
- RC19: `docs/RC19-LAUNCHER-LIFECYCLE-CLOSURE-1.0.md`
- RC20: `docs/RC20-SUPPLY-CHAIN-VULNERABILITY-CLOSURE-1.0.md`
- RC14 release gate: `nmsa/release_assurance.py`
- RC17 signature scope: `docs/RC17-SIGSTORE-BUNDLE-REVIEW-1.0.md`

## Release stop conditions

Until an independent reviewer submits an attributable report and
the explicit owner release decision is separately issued:
`independent_security_review=NOT_RUN` or `PENDING`,
`owner_release_decision=PENDING`,
`production_authorized=false`,
`external_skill_execution_authorized=false`.

Do **not** create a permanent service/scheduled task, change Windows
configuration, auto-install external binaries or update another product
in this review workflow.

**RC21 HANDOFF PACKAGE PREPARED / INDEPENDENT AUDIT PENDING.**
