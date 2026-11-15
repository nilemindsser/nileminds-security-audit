# NMSA v1.0 RC2 — Fail-closed local API contract hardening

## Changes and rationale
Two loopback-only security testing helpers are hardened without accessing
real applications or customer data.

1. API test origin **must** be the literal
   `http://127.0.0.1:PORT`. Names such as `localhost`, IPv6 and alternate
   numeric encodings are rejected rather than resolved via the operating
   system. This reduces hostname/DNS/hosts-file ambiguity.
2. Fixture endpoints accept only simple absolute route paths without queries,
   encoded segments, fragments, dot segments, double-leading slash or
   backslashes. No path-based secrets or dynamic targets are allowed.
3. Config schemas are strict: no arbitrary Authorization values, custom
   headers, unexpected fields, or empty endpoint lists.
4. API HTTP 3xx and 5xx results are marked `INCOMPLETE`.
   The client does not follow redirects. A 302 or 500 cannot produce a
   clean audit status, including for public endpoints.
5. Both API contract probes still use **GET only** and hardcoded,
   deliberately invalid or synthetic fixture tokens. No mutating
   requests or real logins.

## Validation evidence
The updated Python suite contains 63 tests with the locally installed
Semgrep scanner enabled. The new tests cover rejection of alternate
loopback hostnames, userinfo, malformed port and non-local origins,
percent-encoding, traversal, queries, extra schema fields, redirects
and server-side errors. They run in GitHub Actions as well.

## Scope and remaining limits
- These controls only protect the testing harness. They are not an
  application security assessment or a sandbox for untrusted source code.
- Only explicit local fixture HTTP routes are supported; URL-encoded
  application paths are intentionally excluded.
- An HTTP GET can have side effects if a tested application is defective.
  Only test an explicitly started disposable local fixture server.
- The current fake A/B tenant headers are not proof of authentication.
- External skills remain quarantined; runtime Docker isolation remains
  unvalidated as of the previous check.
- Real-world Semgrep precision/recall and independent review remain pending.

**Release status: RC2 code candidate, not production-approved.**
