# NMSA v1.0 RC18 — Internal security integration review and corrective controls

**Review date:** 2026-11-16
**Review class:** Internal code and scanner-assisted assessment, **NOT** an
independent third-party security audit, penetration test or certification.
**Target:** Generic NMSA repository, not any client application.

## Verified finding RC18-F01 — HIGH (resolved in code, pending independent audit)

**Issue:** The original main scanner runner (`nmsa/cli.py`) invoked
Trivy with `--skip-db-update`, yet never examined the installed
vulnerability database `NextUpdate` timestamp. If the installed DB
was expired, Trivy could still return a successful report and NMSA
could show a clean `PASS`. This conflicted with the RC16 fixed-image
workflow, which already blocks on stale database metadata.

**Repair:** Share the existing RC16 `parse_db_next_update` logic.
The main Trivy scanner now checks `trivy --version`, rejects stale,
unparseable or unavailable vulnerability DB metadata *before* running
the scan, and includes explicit `--offline-scan` in its fixed command.
This is fail-closed; it does not automatically update the DB or download
additional scanner tools.

**Evidence:** New integration tests exercise expired/unverifiable DB,
missing coverage, fixed offline flags, valid covered result, and the
full audit's `INCOMPLETE` outcome on expired data. A clean result from
a scanner does not prove complete security coverage.

## Verified finding RC18-F02 — MEDIUM (resolved in code)

**Issue:** The original CLI accepted missing/empty/wrong-shape Semgrep
or Gitleaks structured result data as an empty finding list in certain
successful-exit scenarios. Such data could be interpreted as
`COMPLETE` even though the scanner had not supplied valid evidence
that it evaluated the source.

**Repair:** Require an actual Semgrep `results` array with optional
`errors` array; malformed or missing coverage yields `INCOMPLETE`,
while nonempty `errors` yields `ERROR`. Require Gitleaks result
data to be a list, without treating empty/missing output as `[]`.
The reporting layer already marks a failed/incomplete scanner run
as `INCOMPLETE` for the entire audit.

**Evidence:** Regression tests cover empty, missing and malformed
scanner JSON, secret redaction and correctly structured synthetic
negative results.

## Scanner-assisted code review observations

- Local Semgrep CE run with the **five repository-maintained rule
  packs** over the NMSA source: **0 findings, 0 parser/config errors**,
  process exit 0. This is not a general Python security assessment:
  rule-pack coverage and false negatives remain material limitations.
- Local Gitleaks `dir` scan: **1 candidate finding**
  `cloudflare-api-key`, in `docs/REVIEW-GATE-0.4.md`, line 39.
  Controlled context review established that the marked text is
  explicitly named a Cloudflare **snapshot** and is a
  **40-character hexadecimal Git revision**, with another analogous
  snapshot on the next line. This strongly indicates a *format-based
  false positive*, **not** verified credential leakage. No raw
  candidate value is reproduced here; the value remains in its
  existing commit-history reference until an independent reviewer
  adjudicates the signal. No Gitleaks detector was suppressed.
- Trivy locally installed, but DB metadata had an expired
  `NextUpdate` on 2026-11-15; therefore no up-to-date Trivy
  vulnerability scan is claimed.
- A fixed container restriction fixture passed seven checks in RC11,
  but this did not prove stable Docker lifetime after DeskMCP
  launcher process exit, trusted base image, or containment under
  hostile code execution.

## Additional open audit issues

1. **HIGH / BLOCKED:** Independently verify Docker Desktop process
   survival across terminating DeskMCP launcher sessions.
2. **HIGH / BLOCKED:** Establish trusted image publisher, verified
   signature, image-manifest binding, SBOM and authenticated
   vulnerability database freshness; no blanket trust inferred.
3. **HIGH / BLOCKED:** Independent architecture/code review and
   adversarial negative testing by a separately designated reviewer.
4. **MEDIUM / REVIEW:** The scanner's own Semgrep rules are focused
   and synthetic; additional Python-centric/security review coverage
   and dedicated false-positive benchmark are needed.
5. **LOW / MAINTENANCE:** GitHub Actions emits the previously observed
   Node.js 20 deprecation warning for pinned action major versions;
   upgrade only after verifying compatible revisions separately.

## Verification and authorization

Local **168 Python tests PASS** with Semgrep executable configured;
new RC18 integration/schema tests are included. Real scanner runs
completed as characterized above. GitHub CI results must be checked on
the RC18 PR and not inferred from local tests.

`independent_security_review` and `image_provenance_review` remain
not approved. No production deployment, third-party skill execution,
Docker reset/service installation or unrelated project mutation has
been authorized.

**RC18: INTERNAL FINDINGS REMEDIATED / INDEPENDENT SECURITY REVIEW OPEN /
PRODUCTION RELEASE BLOCKED.**
