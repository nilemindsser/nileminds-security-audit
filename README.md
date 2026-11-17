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

## Storage/data evidence review (v0.9)

Additional Semgrep checks flag public JSON Blob writes and cookies explicitly disabling httpOnly. Scanner output is **not** a verified vulnerability. An opt-in `nmsa.evidence` classifier requires independently reviewed non-production reproduction metadata before classifying an issue as validated (documentation, not cryptographic authorization). See [v0.9 evidence notes](docs/EVIDENCE-GATE-0.9.md).

## v1.0 RC1 — Intra-function JSON data-flow signals

The opt-in Semgrep scan now includes a **Community Edition** taint rule tracking JSON.stringify results to public Blob writes inside the same function, including intermediate variables. It does **not** follow cross-function or cross-file flows. Benchmark: 20 synthetic fixtures; these are not a real-world precision or recall estimate. See [RC1 scope and blockers](docs/RC1-TAINT-1.0.md). Docker isolation is still unverified; external AI skills remain quarantined.

## v1.0 RC2 — Fail-closed API fixture targets

API and tenant contract probes now require literal http://127.0.0.1:PORT and simple path-only routes; unknown configuration fields, URL-encoded traversal, DNS-dependent hostnames, redirects and server errors cannot be treated as clean checks. See [RC2 security hardening](docs/RC2-API-HARDENING-1.0.md). No live APIs tested.

## v1.0 RC3 — Immutable sandbox image ID

The benign Docker fixture now requires NMSA_SANDBOX_IMAGE_ID=sha256:<64-hex> for a verified locally installed image and uses --pull never. A mutable tag is never used to execute the fixture. See [RC3 design and blockers](docs/RC3-IMMUTABLE-SANDBOX-1.0.md). Docker runtime isolation remains unverified.

## v1.0 RC4 — Docker runtime stability gate

python -m nmsa.runtime_gate --samples 3 --delay 2 requires repeated Docker Linux readiness. The fixed sandbox fixture now blocks startup when the engine drops after initially responding; liveness does **not** prove security isolation. See [RC4 runtime report](docs/RC4-RUNTIME-STABILITY-1.0.md).

## v1.0 RC5 — Fixed negative sandbox probes

Run python -m nmsa.sandbox_probes **only** after independently reviewing and preloading a pinned local Docker image. The fixed fixture checks seven restrictions, but it blocks when Docker is unstable, and even a PASS does not certify isolation. See [RC5 probe scope and limitations](docs/RC5-NEGATIVE-PROBES-1.0.md).

## v1.0 RC6 — Read-only Windows Docker diagnostics

Run python -m nmsa.docker_diagnostics for bounded service/context/engine/WSL availability signals without starting services, containers or disclosing raw logs. See [RC6 diagnostics](docs/RC6-DOCKER-DIAGNOSTICS-1.0.md). This does not certify isolation.

## v1.0 RC7 — Privacy-safe Docker log triage

python -m nmsa.docker_log_triage reports bounded, redacted WSL/permission/engine failure-pattern counts from allowlisted local Docker files without publishing log lines, modifying the host or claiming a proven root cause. See [RC7 evidence](docs/RC7-DOCKER-LOG-TRIAGE-1.0.md).

## v1.0 RC8 — Read-only Docker UTC failure timeline

python -m nmsa.docker_timeline correlates bounded local Docker/WSL failure signals into redacted UTC hourly buckets. Time coincidence is not causation or proof of sandbox security. See [RC8 evidence](docs/RC8-DOCKER-TIMELINE-1.0.md).

## v1.0 RC9 — Incident review and safe next action

python -m nmsa.incident_review combines bounded Docker engine and hourly log indicators into a redacted review priority. It never establishes root cause, authorizes remediation or certifies isolation. See [RC9 documentation](docs/RC9-INCIDENT-REVIEW-1.0.md).

## v1.0 RC10 — WSL versus Docker Engine differential

python -m nmsa.wsl_engine_probe uses fixed local Linux uname checks and Docker info to distinguish a WSL outage from a Docker Desktop backend issue. It cannot establish root cause or certify isolation. See [RC10 differential](docs/RC10-WSL-ENGINE-DIFFERENTIAL-1.0.md).

## v1.0 RC11 — Real fixed Node.js sandbox probes

python -m nmsa.node_sandbox_probe --run runs only the fixed Node fixture with a locally preloaded SHA256 image ID and Docker hardening flags. Seven real negative probes passed within one Docker Desktop process session; engine persistence across independent process sessions remains unverified. See [RC11 evidence](docs/RC11-SESSION-LIFECYCLE-SANDBOX-1.0.md). No untrusted skills or app code are authorized.

## v1.0 RC12 — Cross-process Docker readiness

python -m nmsa.cross_session_gate --capture <marker> and --confirm <marker> test Linux Docker liveness from separate processes; a marker is local and untrusted, and success does not prove security isolation. RC12 Windows field check returned BLOCKED because Docker Desktop vanished across DeskMCP process sessions. See [RC12 evidence](docs/RC12-CROSS-SESSION-DOCKER-GATE-1.0.md).

## v1.0 RC13 ? Docker launcher lifecycle evidence

The cross-process gate now labels a successful second-process check as `CROSS_PROCESS_LIVENESS_ONLY`, not proof that Docker survives exit of the launcher session. Controlled Windows checks showed Docker available from a separate process only while the original launcher session remained open. See [RC13 lifecycle evidence](docs/RC13-DOCKER-LAUNCHER-LIFECYCLE-1.0.md). No persistent service was installed or configured.

## v1.0 RC14 ? Release assurance readiness gate

`python -m nmsa.release_assurance` provides a fail-closed evidence-based summary for CI, container behavior, Docker launcher lifecycle, image provenance, independent review and owner release decision. Current snapshot is BLOCKED. Passing all self-declared conditions never auto-authorizes production or execution of third-party skills. See [RC14 release gates](docs/RC14-RELEASE-ASSURANCE-GATES-1.0.md).

## v1.0 RC15 ? Local image identity and provenance precheck

`python -m nmsa.image_provenance --image-id sha256:<64 lowercase hex>` checks bounded local Docker image metadata without executing or pulling images. A matching ID or registry digest does not verify image signatures, software bill of materials, or trusted supply chain. Real cached Node image precheck succeeded, but independent provenance review remains PENDING. See [RC15 evidence](docs/RC15-IMAGE-PROVENANCE-PRECHECK-1.0.md).

## v1.0 RC16 ? Local-only vulnerability review

`python -m nmsa.offline_vulnerability_review --image-id sha256:<64 lowercase hex>` requires an unexpired local Trivy database and performs no DB updates, network dependency lookups, image pulls or container execution. Valid scan results are only REVIEW_REQUIRED; signatures, SBOM and provenance remain unverified. See [RC16 evidence](docs/RC16-OFFLINE-VULNERABILITY-REVIEW-1.0.md).

## v1.0 RC17 ? Offline Sigstore signed-blob review

`python -m nmsa.sigstore_bundle_review` runs a constrained offline Cosign bundle check only when a local signed blob, bundle, independently approved trusted root, signer identity and issuer are supplied. It never accepts identities inferred from the bundle, and signed-blob success never proves Docker image provenance or authorizes production. Cosign and trusted artifacts are currently missing; see [RC17 evidence](docs/RC17-SIGSTORE-BUNDLE-REVIEW-1.0.md).

## v1.0 RC18 ? Internal security integration review

The main CLI scanner now checks Trivy DB freshness using the shared RC16 policy and refuses to treat missing Semgrep, Gitleaks, or Trivy report coverage as a clean result. Scanner-assisted self-review found a likely false-positive Gitleaks signal on a documented Git SHA snapshot; no detector was suppressed. This is an *internal* assessment, not independent certification. See [RC18 audit](docs/RC18-SECURITY-INTEGRATION-REVIEW-1.0.md). Production and external skills remain blocked.

## v1.0 RC19 ? Docker launcher lifecycle closure evidence

Repeated controlled tests established 3/3 Docker readiness while its initiating DeskMCP session stayed alive and 0/3 once it exited. The exact cause is not proven. `nmsa.cross_session_gate` now exits nonzero for `CROSS_PROCESS_LIVENESS_ONLY` so scripts cannot treat a second process as successful launcher-session persistence. Docker stability and production readiness remain BLOCKED. See [RC19 report](docs/RC19-LAUNCHER-LIFECYCLE-CLOSURE-1.0.md).
