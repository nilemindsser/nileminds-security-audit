# NMSA JavaScript / Node.js / Vercel and API contracts (v0.6)

## Scope

Custom offline Semgrep rules (13 total including original Python rules) target:
- JavaScript `eval(...)` and `new Function(...)` (review dynamic execution)
- Node.js shell execution (`child_process.exec/execSync`) and disabled TLS validation
- risky deserialization and a narrow Express wildcard CORS idiom
- Vercel/Next.js server-route response wildcard CORS or header reflection
- accidental public environment variables with secret-like names
- a narrow explicit unconditional admin bypass signature

These are **heuristic audit leads**, not proof of exploitable vulnerabilities.
Many real authorization bugs, SSRF, injection chains, tenant isolation flaws,
and Vercel routing misconfigurations require deeper data-flow/manual review.
The admin-bypass rule is intentionally narrow and NOT a general auth audit.
Check both `middleware.ts` and `proxy.ts` in modern Next.js projects.
No application was patched.

The built-in local rules live in `nmsa/rules-js.yml` and
`nmsa/rules-vercel.yml`. The orchestrator automatically enables them with
the existing Python rules, without contacting a rule registry. The rules
use Semgrep CE and do not require a paid subscription.

## Independent API contract probe

This separate offline-capable Python module checks only a deliberately
started **local loopback test server**. It rejects public and private remote
hosts, SSL endpoints, credentials in URLs, non-loopback addresses and redirects.

Example of a *test environment only*:

```json
{
  "endpoints": [
    {"path": "/api/admin/me", "access": "protected"},
    {"path": "/api/health", "access": "public"}
  ]
}
```

Save as `contract.json` outside a project, start a local development mock
server at `http://127.0.0.1:PORT`, then:

```powershell
python -m nmsa.api_contract --base http://127.0.0.1:PORT --spec contract.json --output report.json
```

Only GET is issued. For protected routes an intentionally **invalid** Bearer
token must produce 401 or 403; other responses require manual review.
The probe also checks suspicious CORS configurations and response stack traces.
It stores only HTTP status and selected finding labels; never response bodies,
tokens, or live application credentials.

**Restrictions:** These checks do not prove that unauthenticated access is
rejected, do not test valid-user role escalation or IDOR, do not mutate state,
and cannot guarantee GET endpoints are side-effect free. Use only locally
controlled fixture servers. Do not point this tool at NileMenu production or
other live services. Do not confuse `OBSERVED_NO_FINDINGS` with a security PASS.

## Validation evidence

- 13 rules syntactically validated using Semgrep CE 1.184.0 on Windows.
- An isolated synthetic JS test input triggered 5 targeted rules.
- Local API mock tests cover protected endpoints, permissive CORS,
  error leakage, remote URL rejection, unsafe paths, and unreachable targets.
- Tests are run in the normal Python suite and in a separate GitHub
  workflow installing the pinned community scanner.

## Follow-up

1. Add tenant-aware auth/IDOR testing with explicit user-supplied test
   identities and non-production fixtures.
2. Expand framework-specific rules with positive and negative cases to
   measure false alarms and misses.
3. Run on NileMenu only under a separate read-only task using
   a pinned checkout, not as part of this generic-tool release.
4. Preserve human review, source evidence, and the existing skill quarantine.
