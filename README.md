# Nile Minds Security Audit (NMSA)

A project-agnostic, evidence-first **local security audit orchestrator**. Open source, zero paid services required for its basic operation. **Early MVP, not a security certification.**

## Goals
- One entry point for **Semgrep Community Edition**, **Gitleaks**, and **Trivy**
- Machine-readable JSON and human-readable Markdown reports
- Explicit **INCOMPLETE** status when a scanner is missing, times out, or errors
- No secrets, source excerpts, raw scanner logs, cloud upload, or auto-remediation in generated reports

## Quick start

Requires Python 3.10+ and separately installed scanner binaries on PATH. Consult the scanners' official documentation for installation and licensing.

```sh
python -m nmsa /absolute/path/to/project --output /absolute/path/to/existing-audit-output
python -m unittest discover -s tests -v
```

Outputs: `SECURITY-AUDIT.md`, `security-audit.json`, `security-audit.sarif` and `security-audit.html`. The output directory **must already exist outside the project**.

**Status**: PASS = no findings from enabled successful scanners; REVIEW = non-high findings; FAIL = high/critical findings; INCOMPLETE = one or more scanners unavailable or failed. PASS does **not** mean secure.

## Architecture

The CLI uses an allowlist of installed scanners, argument-vector execution (no shell), per-scanner timeouts, parsers, and location-based evidence aggregation. CodeQL is **not** included by default; its licensing/use restrictions vary. AI skill frameworks from Cloudflare and other projects are **not executed** by this MVP; they require provenance, license, prompt-injection, and sandbox review first.

Trivy is launched with database-update disabled to avoid automatic network downloads. Its vulnerability coverage will be incomplete until databases are provisioned in a controlled workflow. Semgrep uses bundled minimal local rules; full SAST coverage is not implied. Network isolation of scanner processes must be enforced externally.

## Safety and known limits

- Execute scanners only against trusted project paths in a sandbox/least-privilege account. This tool **does not** provide OS sandboxing by itself.
- Reports omit secret values but may contain relative filenames and rule identifiers; treat reports as confidential.
- Initial deduplication matches identical rule/path/line, not semantic duplicate vulnerabilities across different scanners.
- Scanner exit conventions and JSON versions vary. Validate pinned versions before production use.
- First version does not verify exploitability, inspect AI agent prompt injections, or claim measured precision/recall.
- Offline operation is **not guaranteed** for all scanners until sources/rules/databases are pinned and cached.
- No automated publishing or code changes from scans.

See [architecture](docs/ARCHITECTURE.md), [license notes](docs/THIRD_PARTY.md), and [security policy](SECURITY.md).

## Governance
Generic tool for any project. No hidden dependency on a particular client, project, or company repository. Never merge security changes without owner approval.

For current v0.2 scope see [release notes](docs/RELEASE-0.2.md) and [Windows installation](docs/INSTALL-WINDOWS.md).

## Third-party skill quarantine (v0.3)

Run python -m nmsa.skill_review PATH_TO_SOURCE --output PATH_TO_EXTERNAL_MANIFEST.json to inventory a cloned skill package without executing it. All external skills remain disabled. See [skill review](docs/SKILL-REVIEW-0.3.md).

## Manual skill review gate (v0.4)

Use python -m nmsa.review_gate prepare SOURCE --review EXTERNAL_FILE.json, then python -m nmsa.review_gate verify SOURCE --review EXTERNAL_FILE.json. Review records never authorize execution. See [v0.4 review gate](docs/REVIEW-GATE-0.4.md).
