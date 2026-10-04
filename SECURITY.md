# Security Policy

## Supported Versions

Security fixes are applied to the `main` branch and the latest release tags.

## Reporting a Vulnerability

Please do **not** open a public issue for suspected vulnerabilities.

1. Open a private security advisory in GitHub Security for this repository.
2. Include impact, reproduction steps, and affected commit SHA/tag.
3. Provide a proposed fix if available.

We will acknowledge reports and triage severity as quickly as possible.

## Secure development baseline

- Fail closed by default for authorization paths.
- Require signed, single-use permits and hash-bound call validation.
- Keep auditable, tamper-evident logs.
- Require code-owner review before merge to `main`.
