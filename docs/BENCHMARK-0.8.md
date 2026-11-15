# NMSA v0.8 — Reproducible synthetic rule benchmark

A first transparent benchmark for custom Semgrep CE rules. Each of 12
locally authored JavaScript cases is labeled with a specific expected
rule and whether it should fire. No fixture code is executed.

| Measure | Local result |
|---|---:|
| True positives (TP) | 6 |
| False positives (FP) | 0 |
| False negatives (FN) | 0 |
| True negatives (TN) | 6 |
| Precision | 1.0 |
| Recall | 1.0 |

Six targeted patterns: eval, dynamic Function constructor, disabled TLS
certificate verification, child_process.exec, wildcard CORS, public Blob
writes under data/.

**Interpretation:** The values reflect *only 12 purpose-built toy cases*.
They are not independent benchmark results, do not estimate the prevalence
of false positives on real repositories, and cannot establish that a rule
detects all meaningful vulnerability variants. They are diagnostic regression
tests, not a security certification.

Reproduce on a machine with Semgrep CE available on PATH or via
NMSA_SEMGREP_BIN:

```powershell
python -m nmsa.benchmark --output D:\NileMinds\nmsa-benchmark-v08.json
```

GitHub workflow runs this on Ubuntu with pinned Semgrep CE 1.184.0.

Important limits:
- Checks are for specific rule behavior, not exploitability.
- Synthetic examples may underrepresent obfuscation, real-world input flow,
  framework semantics, and difficult true negatives.
- Other installed rules do not yet have this benchmark coverage.
- No access to live endpoints, customer data, or production credentials.
- Cloudflare and Security Audit Skills remain quarantined.
