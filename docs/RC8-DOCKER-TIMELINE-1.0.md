# NMSA v1.0 RC8 — Privacy-safe Docker/WSL UTC timeline

## Measured result (2026-11-15)

A read-only analyzer processed four allowlisted local Docker log files.
It found 12,728 lines carrying supported timestamps, with nine matching
WSL failure-indicator lines grouped into two hourly UTC windows:

| UTC hour | WSL indicator lines | Distinct log sources |
|---|---:|---:|
| 2026-11-10T22:00Z | 1 | 1 |
| 2026-11-15T10:00Z | 8 | 3 |

The latter coincides broadly with the earlier Docker Desktop startup
and subsequent Linux daemon failure attempts. The analysis **does not
prove WSL caused the shutdown**, or that these messages are independent.
Log timestamp/timezone correctness, retry duplication and event ordering
are unverified.

## Implementation

`python -m nmsa.docker_timeline` analyzes bounded local files from the
pre-existing RC7 allowlist. It accepts bracketed RFC3339 timestamps or
common timestamp-bearing JSON records and normalizes them to UTC hours.
It returns only coarse date-hour buckets, matched category counts,
distinct log-source counts and coverage statistics.

Controls:
- No dynamic arbitrary log paths via the CLI, no files modified.
- Does not emit full log messages, host paths, usernames, tokens or IPs.
- Reuses RC7 symlink, directory boundary and maximum-file-size checks.
- Only the last twelve distinct signal-bearing hours are emitted.
- Missing/invalid timestamps are not guessed or counted.
- Output always states `root_cause_confirmed:false` and
  `isolation_verified:false`; an empty result is `INCOMPLETE`.

## Verification and outstanding gates

- 100 Python tests PASS locally with Semgrep enabled.
- The timeline provides limited incident-window correlation, **not**
  a causal diagnosis or permission to remediate.
- Docker daemon remains unconfirmed stable; RC5 behavioral probes not
  executed; source/image trust review and independent audit pending.
- No changes to Docker/WSL system configuration, application repositories
  or external security skills.

**RC8 release candidate is not an authorization to run untrusted skills.**
