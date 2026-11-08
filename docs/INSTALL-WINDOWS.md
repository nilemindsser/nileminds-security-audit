# Windows setup (manual, least privilege)

The orchestration package is Python standard-library only. Install each scanner from its official source and verify its publisher, hashes and license.

1. Install Gitleaks from its official GitHub release.
2. Install Semgrep Community Edition in a dedicated Python environment using `py -3.12 -m venv <outside-project-path>` and then `<venv>/Scripts/python -m pip install semgrep`. Set `NMSA_SEMGREP_BIN` to the full path to semgrep.exe if it is not on PATH.
3. Install Trivy using its [official Windows binary](https://trivy.dev/docs/latest/getting-started/installation/) or the verified AquaSecurity.Trivy WinGet manifest. Restart the terminal to refresh PATH. Set `NMSA_TRIVY_BIN` if needed.
4. Provide Trivy vulnerability databases through an approved cache management workflow. The orchestrator disables automatic DB updates. With empty/outdated databases, scanning may fail; report must say INCOMPLETE, not PASS.
5. Create a distinct output directory outside the source project. Example (PowerShell):

```powershell
New-Item -ItemType Directory D:\Audits\example -Force
$env:NMSA_SEMGREP_BIN = 'D:\Tools\semgrep-venv\Scripts\semgrep.exe'
python -m nmsa D:\Projects\example --output D:\Audits\example
```

**Security notice:** This program starts local third-party tools. It does not sandbox their filesystem or network access; scan untrusted code only inside an external isolated VM/container. Semgrep uses bundled local rules by default (starter ruleset, *not* broad security coverage). Trivy uses `--skip-db-update`. Never treat a clean report as proof of security.
