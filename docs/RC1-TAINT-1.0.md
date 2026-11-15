# NMSA v1.0 RC1 — Intra-function JSON-to-public-Blob tracing

**Release candidate only. Not approved for unrestricted production security auditing.**

## Addition

Semgrep CE taint rule `nmsa.storage.json-to-public-blob-same-function`
tracks `JSON.stringify(...)` output to a `put(..., body,
{access:"public"})` sink, including assignment to an intermediate
variable **within the same function**. The sink focuses on the payload
rather than the object path.

This is a *data exposure review signal*, not evidence that the serialized
object is sensitive or that the public URL was actually accessed.
JSON may intentionally contain public menu/marketing content.

The rule cannot reliably trace across function boundaries, module
imports, storage adapters, database access, or application authorization
layers. Cross-function or cross-file tracking must not be promised as
part of Semgrep CE validation. Sensitive data reaching Blob storage
without a JSON.stringify expression may also be missed.

## Synthetic acceptance evidence

Benchmark updated to 20 labeled toy cases: 10 expected-positive, 10
expected-negative. Local observed TP=10 FP=0 FN=0 TN=10.
This is a regression fixture, **not** real-world precision/recall.

The added cases cover JSON serialization followed by a public Blob
write via a local variable, the same via an inline expression, a
private Blob write, and an unrelated public payload variable.

## NileMenu — confidential, read-only snapshot observation

Pinned private checkout: `eb26675b5d80e9b4bc5a507fb0510896e8fdead2`.
The private source was scanned read-only; no production endpoint queried.
This public tool repository does not include source text or the complete
private findings. The local private report identifies two new rule
signals at different Blob writes, one for intentionally public menu
data and one for generic data storage. Existing public Blob pattern
signal remains. **None is independently validated as exploitation.**

Private report location:
`D:\NileMinds\nmsa-nilemenu-audit-v10-rc1`

The menu record may legitimately be publicly readable. Other data
storage must be classified by resource and reviewed for disclosure
risk using non-production disposable examples. Do not automatically
mark all public JSON blobs as vulnerabilities.

## Release gates

- Syntax validation of all local rule packages
- All unit tests and fixture benchmark in GitHub CI
- Scan of pinned private copy without modifying it
- Review of scanner errors and report sanitization
- Verified Docker sandbox runtime isolation **pending**:
  local Linux Docker daemon was unavailable at this check.
- Independently reviewed realistic security accuracy benchmark **pending**
- Individual triage of external skill signals **pending**

Third-party AI skill execution stays quarantined.
