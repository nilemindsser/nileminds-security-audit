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

## Offline triage and prompt-injection fixtures (v0.5)

Run python -m nmsa.triage INVENTORY.json --output TRIAGE.json to prioritize static review signals without executing source. Pattern-based prompt-injection checks are tested with synthetic fixtures only. See [v0.5 report](docs/TRIAGE-0.5.md). No external skill is authorized.

## Restricted sandbox preview

python -m nmsa.sandbox checks Docker Linux daemon readiness. python -m nmsa.sandbox --run-fixture executes a fixed benign fixture only when a locally preloaded image exists. This is NOT a validated security boundary and cannot run external skills. See [sandbox preview](docs/SANDBOX-0.5.md).

## JavaScript / Node.js / Vercel and API contracts (v0.6)

All bundled JS and Vercel Semgrep rules run automatically alongside Python rules. API contract probes are a separate opt-in **loopback-only** GET utility: python -m nmsa.api_contract --base http://127.0.0.1:PORT --spec contract.json --output report.json. This is not an authorization pen test. See [v0.6 security scope](docs/JS-API-SECURITY-0.6.md).

## Tenant isolation fixtures (v0.7)

python -m nmsa.tenant_contract --base http://127.0.0.1:PORT --spec fixtures.json --output report.json runs **synthetic A/B identity GET-only** tests against an explicitly launched local mock service. Not safe to point at a production service or assume it proves RLS/IDOR security. See [v0.7 contract test design](docs/TENANT-AUTH-CONTRACTS-0.7.md).

## Synthetic Semgrep benchmark (v0.8)

Run python -m nmsa.benchmark --output benchmark.json with Semgrep CE installed. The benchmark currently covers six rules on twelve labeled toy cases and produces TP/FP/FN/TN plus precision and recall. See [benchmark limitations](docs/BENCHMARK-0.8.md). This is not a real-world security accuracy measurement.
