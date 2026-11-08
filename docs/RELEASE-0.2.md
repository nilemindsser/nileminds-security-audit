# v0.2 integration status

## Implemented
- Configurable local allowlisted executables: `NMSA_SEMGREP_BIN`, `NMSA_TRIVY_BIN`, `NMSA_GITLEAKS_BIN` if not on PATH.
- Minimal bundled Semgrep rules to avoid fetching `auto` registry rules.
- Read-only intent and shell-free process launch with timeout and UTF-8 decoding tolerant of Windows scanner output.
- Four output formats: sanitized JSON, Markdown, SARIF 2.1.0 and self-contained HTML with escaped untrusted fields.
- An incomplete scanner fails the aggregate audit (INCOMPLETE).
- Structured parser tests, HTML escaping and SARIF tests.

## Limits
- Trivy intentionally disables automatic vulnerability DB downloads. A missing DB yields ERROR/INCOMPLETE; DB provisioning is a separate controlled task.
- Minimal Semgrep rules are starter examples, not comprehensive security rules.
- No OS sandbox, no proof of network isolation, and no exploitation/independent vulnerability confirmation.
- AI skill integrations, CodeQL, semantic deduplication and precision/recall benchmarks remain planned, not implemented.
- The system deliberately does **not** expose raw scanner output, matched secret values, or source excerpts.

## Acceptance gates
- Unit tests PASS.
- Integration scan with Gitleaks and Semgrep: run and record evidence.
- Trivy with verified current DB: pending.
- Full-stack scan is READY only when all requested scanners are COMPLETE and evaluated by a human reviewer.
