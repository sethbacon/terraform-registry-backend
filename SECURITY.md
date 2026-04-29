<!-- markdownlint-disable MD013 -->
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

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

## Repository Hardening

The following GitHub repository controls are configured for `main` to protect
the release pipeline and supply chain:

### Branch Protection (`main`)

- Required status checks (strict — branch must be up-to-date): `Backend Tests & Quality`, `Security Scan (gosec)`, `Docker Build Smoke Test`, `Deployment Config Validation`, `Conventional PR Title`
- Required pull request reviews: 1 approving review, dismiss stale reviews, require code-owner review
- Required conversation resolution: yes
- Force pushes: blocked; branch deletion: blocked
- The `terraform-registry-release-bot` GitHub App is allowed to bypass for release commits and tags

### Merge Strategy

- **Squash merge only** — rebase merges and merge commits are disabled
- Delete branch on merge: enabled
- Allow update branch: enabled
- Web commit signoff (DCO) required for web-based commits

### Dependency Management

- Dependabot vulnerability alerts: enabled
- Dependabot automated security fixes: enabled
- Dependabot version updates configured via `.github/dependabot.yml` (Go modules and GitHub Actions, biweekly)

### Code Ownership

- `.github/CODEOWNERS` requires explicit owner review for `backend/`, `.github/`, `deployments/`, and `.goreleaser.yml`

### Supply-Chain Security

- All GitHub Actions pinned to full commit SHAs
- Secret scanning + push protection: enabled
- gosec security scanning in CI with baseline drift detection (`scripts/gosec-compare.py`)
- `go vet` and race-detector-enabled tests in CI
- Scheduled weekly security workflow with auto-issue on failure
- **SLSA provenance attestation** on Docker images and GoReleaser binaries via `actions/attest-build-provenance`
- **SBOM generation** via syft in GoReleaser
- **Cosign keyless signing** on Docker images and checksum files via Sigstore (verify with `cosign verify`)
