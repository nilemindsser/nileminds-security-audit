# NMSA v0.7 — Authorization and tenant isolation contract fixtures

## Goal
Add independent, evidence-first checks for cross-tenant access within
**explicitly started local mock services**. This work applies generally
to multi-tenant systems; it is not coupled to NileMenu or any customer project.

## Implemented
- `nmsa/tenant_contract.py`: Python standard-library, opt-in GET-only
  loopback tester with exactly two synthetic principals `A` and `B`.
- An owned resource baseline must return HTTP 200 for the synthetic
  owner and 403/404 to the other synthetic principal.
- An unexpected 2xx or 401/redirect on the other principal produces
  `CROSS_TENANT_ACCESS_REVIEW`; a missing/failed owner baseline
  produces `INCOMPLETE`, never a clean result.
- Results contain route identifiers and observed statuses only.
  No response body, personal information or actual credentials.
- Requests reject remote hosts, credentials in URLs, redirects,
  unsafe paths, and identities outside the fixed fixture tokens.
- CI tests a local fixture server with both safe and intentionally
  broken tenant routes.

Example fixture specification (synthetic only):
```json
{"cases":[{"path":"/case/a","owner":"A","other":"B"},
          {"path":"/case/b","owner":"B","other":"A"}]}
```

Example usage:
```powershell
python -m nmsa.tenant_contract --base http://127.0.0.1:PORT --spec local-fixtures.json --output local-results.json
```

## Evidence and interpretation
The fixture tests demonstrate that the probe distinguishes an owner
200/other 403 or 404 from owner 200/other 200, and refuses an
unverified owner baseline. This is **contract testing**, not a proof of
correct database RLS, object-level authorization, JWT verification, or
absence of IDOR in a real deployment.

Security verdicts are observations requiring human review.
No real tenant identities, administrator sessions, live services or
production data were used.

## Existing safeguards
All external AI skills remain quarantined. The v0.5 sandbox preview
has not passed a real-world network/host-isolation assessment. No
integration here executes third-party skills or modifies scanned projects.

## Pending for production use
- Authenticated multi-role tests with purpose-built disposable accounts
  and explicit owner authorization.
- Resource ownership fixtures spanning list, detail, mutation, upload,
  export and deletion lifecycle (not performed against real services).
- Validated defense against DNS rebinding, HTTP redirects and service
  misidentification beyond the loopback-only lab.
- A Semgrep precision/recall benchmark with a wider, independently
  labeled corpus.
- Independent review of found issues and remediations.
