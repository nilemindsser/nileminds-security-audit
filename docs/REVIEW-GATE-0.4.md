# v0.4 — Manual review gate and prompt-injection controls

## Gate contract
The review system prepares a JSON checklist from a source inventory pinned to
Git commit plus SHA-256 fingerprint of the inventoried files and signal list.

**No part of this program activates or executes third-party skills.** Even if
every review entry is marked BENIGN_EXAMPLE, the maximum attainable state is
`REVIEW_DOCUMENTED_NOT_AUTHORIZED`. Activation must be implemented as a separate
sandboxed adapter after explicit owner approval. No such adapter exists.

### Workflow

```powershell
python -m nmsa.review_gate prepare D:\NileMinds\nmsa-sources\cloudflare-security-audit-skill --review D:\NileMinds\nmsa-skill-review-results\cloudflare-review.json
python -m nmsa.review_gate verify D:\NileMinds\nmsa-sources\cloudflare-security-audit-skill --review D:\NileMinds\nmsa-skill-review-results\cloudflare-review.json
```

1. Edit checklist entries only after an independent **manual** inspection of the
   specific file and line. Keep reasons concise and do not copy source secrets.
2. Allowed triage decisions: `UNREVIEWED`, `BENIGN_EXAMPLE`,
   `REQUIRES_MITIGATION`, `CONFIRMED_RISK`.
3. Check `requested_permissions` against the explicit known permission list.
4. File or signal changes invalidate the fingerprint; commit changes fail the gate.
5. No approvals may be inferred from checked boxes, a numeric score, or the name
   of a reviewer. This register is editable plaintext, not signed authorization.
6. Any unknown permission, changed signal identity, or execution_authorized=true
   triggers `BLOCKED`. Unsatisfied review triggers `MANUAL_REVIEW_REQUIRED`.

## Prompt-injection review
Heuristic checks identify possible attempts to override prior instructions.
These are **text signals** only: example instructional content can trigger them,
and obfuscated or multilingual attacks may evade them. A human reviewer must
inspect contextual meaning without executing third-party scripts. Prompt tests
cover representative malicious instructions in **locally authored fixtures**,
not benchmark recall or resistance of a live LLM agent.

## Source evidence
Cloudflare snapshot: `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`.
Security Audit Skills snapshot: `ec55ea14b966cf72f8f69bf9bf228a04189b73fe`.
See `SKILL-REVIEW-0.3.md` for initial signal counts. Exact review templates
are kept locally and are not published to this repository.

## Not complete
- Individual triage of 235 findings and verification of any real compromise
- Enforced OS sandbox, network isolation, secrets isolation
- Real-world prompt injection benchmark on agent behavior
- Cryptographic review authorization or immutable audit log
- Activation adapter for external skills

Gate: **QUARANTINED / NOT READY TO EXECUTE**.
