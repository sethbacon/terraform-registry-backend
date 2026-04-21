# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.7.x   | :white_check_mark: |
| < 0.7   | :x:                |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, please report them privately using one of these methods:

1. **GitHub Security Advisories** — Use the "Report a vulnerability" button on the
   [Security tab](../../security/advisories) of this repository.
2. **Email** — Send details to the repository maintainers listed in `CODEOWNERS`.

### What to Include

- Description of the vulnerability
- Steps to reproduce (proof of concept if possible)
- Affected versions
- Potential impact

### Response Timeline

- **Acknowledgement:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix or mitigation:** targeting 30 days for critical/high severity

### Disclosure Policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
We will credit reporters in the release notes unless anonymity is requested.

## Security Practices

- All releases include SHA-256 checksums and SLSA provenance attestations
- Container images are signed with [cosign](https://github.com/sigstore/cosign)
- Dependencies are monitored by Dependabot (Go modules, GitHub Actions, Docker)
- Static analysis via `gosec` runs on every PR with baseline drift detection
- The application follows OWASP Top 10 mitigations (parameterised queries,
  input validation, CSRF protection, rate limiting, audit logging)

## Threat Model

A comprehensive STRIDE-based threat model is maintained at
[docs/threat-model.md](docs/threat-model.md). It covers trust boundaries, data
flow diagrams, per-category threat analysis, assumptions, and residual risks.
