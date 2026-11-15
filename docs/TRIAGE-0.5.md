# NMSA v0.5 — initial triage and prompt-injection fixture checks

## Evidence sources
- Cloudflare security-audit-skill: pinned `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`
- Security Audit Skills: pinned `ec55ea14b966cf72f8f69bf9bf228a04189b73fe`

The inputs are the saved v0.3 inventories. The v0.5 engine DOES NOT
execute either external repository. All indicators remain UNVERIFIED.

## Prioritization (not vulnerability severity)

| Source | Total signals | P0 | P1 | P2 |
|---|---:|---:|---:|---:|
| Cloudflare | 7 | 0 | 3 | 4 |
| Security Audit Skills | 228 | 8 | 136 | 84 |
| Total | 235 | 8 | 139 | 88 |

Context heuristic (Security Audit Skills): 22 source, 57 test/example,
149 documentation signals. These categories are syntactic and may misclassify
fixtures that do not use a standard test directory name.

The eight P0 signals were located in:
- `scripts/score_audit.py` (line 24)
- `scripts/selftest_patterns.py` (lines 62, 611, 612, 685, 692, 771)
- `skills/security-audit/scripts/pr_diff_scope.sh` (line 33)

The references in `selftest_patterns.py` are likely test-related by
filename, but **that has not been proven** by reading and evaluating the code.
No P0 signal is a confirmed malicious finding. None is cleared automatically.

## Prompt injection fixtures
Static recognition checks verify common classes:
- fake high-priority system/developer instructions
- requests to override previous instructions
- requests to transmit credentials
- requests to turn off safety controls
- instructions to invoke a shell

These tests measure **pattern matching on synthetic examples**, NOT
the resistance of a real assistant to injection. Output includes categories
and line numbers only, never copied payloads.

## Safety & remaining work
- Triage is read-only and cannot activate external skills.
- Manual review remains required for **all 235** indicators.
- Source hash and approval gates from v0.4 remain unchanged.
- Independent sandbox with denied network, secrets and writable project
  mounts is NOT implemented; therefore execution of external skills
  is NOT authorized.
- Next gate: manual triage with evidence, then sandbox enforcement and
  behavioral red-team benchmarks.

Run:
```powershell
python -m nmsa.triage D:\NileMinds\nmsa-skill-review-results\cloudflare.json --output D:\NileMinds\nmsa-skill-review-results\cloudflare-triage-v05.json
```
