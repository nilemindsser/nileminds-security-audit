# NMSA v1.0 RC14 — Release assurance gates

## Purpose

Make the release eligibility blockers inspectable and deterministic,
without equating CI success or limited container checks with production
security certification. NMSA is a general-purpose Nile Minds tool,
not a project-specific Al-Moheeb/NileMenu integration.

## Implementation

`python -m nmsa.release_assurance` evaluates a fixed evidence snapshot
declared from previous verified milestones. **It does not fetch live
GitHub CI data** and cannot authorize a deployment.

Required categories:
1. Code/test CI result
2. Synthetic security rule benchmark
3. Real fixed container restriction probes
4. Docker launcher-session exit persistence
5. Container image provenance/security review
6. Independent security review of NMSA
7. Explicit owner release decision

The record uses only PASS / FAIL / NOT_RUN / PENDING / UNKNOWN.
Missing, additional, or malformed fields are rejected. Any unfulfilled
condition yields `BLOCKED`. Even an all-PASS self-reported record
yields only `REVIEW_REQUIRED`, never `production_authorized:true`.

This distinction is essential: supplied strings and locally generated
markers are not signed evidence or proof of independent approval.

## RC13 evidence snapshot (not a live reading)

| Gate | Status | Evidence |
|---|---|---|
| Code/CI | PASS | PR #17: six of six checks passed |
| Synthetic benchmark | PASS | Rule fixtures passed in CI |
| Real container behavior | PASS | RC11: seven of seven fixed negative probes passed in one session |
| Launcher exit persistence | FAIL | RC13: Docker unavailable after launcher DeskMCP shell ended |
| Image provenance review | PENDING | No independent signed image/supply-chain validation |
| Independent security review | NOT_RUN | Independent assessment not completed |
| Owner release decision | PENDING | No production approval granted |

**Overall: BLOCKED.** No external skill execution or production use
is authorized.

## RC14 validation

- Local unit suite with Semgrep enabled: **135 PASS**.
- Existing 17 Semgrep rule set and synthetic benchmarks remain in CI.
- New release gate does not run containers, mutate the host, start
  background services, download images, or copy raw machine data.
- Deployments and external tools are not modified.
- Before final release: verify fresh CI, independent supply-chain review,
  controlled launcher-exit evidence and security review, then obtain
  an explicit owner approval outside the self-reported tool state.

## Notes on GitHub repository

Existing repository: `nilemindsser/nileminds-security-audit`.
No duplicate repository should be created. The repository currently
reports Public visibility; do not add sensitive evidence or source
secrets to it. Changes to its visibility require separate owner
authorization.
