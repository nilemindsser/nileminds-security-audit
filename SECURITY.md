# Security policy

Do not submit real secrets in issues, logs or screenshots. Report suspected security issues privately to repository maintainers using GitHub security advisories/private vulnerability reporting when available.

The scanner launcher runs third-party binaries and may parse untrusted projects. Operate inside an isolated environment with minimal permissions. The initial MVP does not enforce filesystem or network confinement, so it is **not safe to run on untrusted repositories without external sandboxing**.

Generated findings omit matched secret values, source snippets, and raw stderr. Scan artifacts may still reveal sensitive paths/rule metadata. Review before publishing.
