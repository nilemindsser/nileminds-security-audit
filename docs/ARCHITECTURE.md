# NMSA architecture v0.1

## Phases
1. Detect installed local scanners (no auto-install).
2. Run allowlisted executables with structured argv, bounded timeouts, read-only *intent*.
3. Parse only structured outputs and discard raw messages that may contain credentials.
4. Normalize tool, rule, severity, relative path and line.
5. Deduplicate exact same (path, line, rule) while preserving scanner provenance.
6. Fail closed to INCOMPLETE when any requested scanner is unavailable/errored.
7. Write JSON and Markdown report outside target.

## Roadmap (not implemented)
- SARIF import/export, schema tests, version pinning and cache integrity.
- Risk acceptance workflow and false-positive review.
- Controlled air-gapped scanner execution with network denial.
- Independent security triage of scanner output.
- Sandboxed AI review skills only after provenance and prompt injection audit.
- CodeQL opt-in with license eligibility control.
- Integration adapters for NM-PEM gates, NM-CAE orchestration, NM-AEVAL benchmarking, MASTER reporting.

## Evidence status
Working code: Python CLI and parser unit tests.
Not proven: benchmark sensitivity, false-positive rates, compatibility of all scanner versions, continuous integration on live repository.
