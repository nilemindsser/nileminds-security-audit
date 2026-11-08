# External skill review — v0.3

**Decision: QUARANTINED / MANUAL_REVIEW_REQUIRED. No execution authorized.**

These inventories were generated from local shallow clones. Cloning and reading the
files **did not install or run** either skill package.

| Upstream | Pinned commit | Files inventoried | Heuristic signals | Execution |
|---|---|---:|---:|---|
| [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill) | `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` | 22 | 7 | DISABLED |
| [security-audit-skills](https://github.com/ashrafiucse/security-audit-skills) | `ec55ea14b966cf72f8f69bf9bf228a04189b73fe` | 527 | 228 | DISABLED |

## Signal breakdown
- Cloudflare: executable file review 4, credential references 2, dynamic execution 1.
- Security Audit Skills: credential references 90, executable file review 52, dynamic execution 35, network command 32, shell pipelines 18, instruction override 1.

**Important:** Counts represent pattern occurrences in file lines and executable file
inventory, **not** confirmed vulnerabilities. Patterns often match examples or
security documentation. No false-positive/true-positive triage has yet occurred.

## Reproduce
```powershell
python -m nmsa.skill_review D:\NileMinds\nmsa-sources\cloudflare-security-audit-skill --output D:\NileMinds\nmsa-skill-review-results\cloudflare.json
python -m nmsa.skill_review D:\NileMinds\nmsa-sources\security-audit-skills --output D:\NileMinds\nmsa-skill-review-results\security-audit-skills.json
```

Both source clones and JSON outputs are outside this public repository and are not published.
Only SHA256, relative paths, rule category and line numbers appear in manifests; no excerpts,
secret matches, or source code are included.

## Gates before activation
1. Verify exact upstream commit and applicable license, including bundled dependencies.
2. Manually review executable files, prompts, shell/network behavior, and all signals.
3. Review whether each proposed skill can alter files, request credentials, or exfiltrate data.
4. Test only with mock fixtures in an isolated sandbox with explicit network restrictions.
5. Obtain written owner approval for the exact hash/permissions/skill.
6. Implement an **independent sandboxed activation adapter** with allowlisted operations.
7. Validate benchmark performance and produce independent review evidence.

The inventory tool **cannot execute skills**. Approval documents alone must not bypass it.
