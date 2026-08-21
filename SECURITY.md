<!-- markdownlint-disable MD013 -->
# Security Policy

## Supported Versions

We support the latest `3.x` minor/patch release. Earlier major versions do not
receive security fixes; upgrade to the latest `3.x` release before reporting
an issue against an older version.

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | :white_check_mark: |
| < 3.0   | :x:                |

This table is refreshed as part of the release-please version-bump PR whenever
the supported major version changes.

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

- All GitHub Actions are pinned to full commit SHAs. Some are pinned **in this repository**
  (`.github/workflows/`) and some in the shared workflows this repository calls — see
  *Shared CI workflows* below. Checking only `.github/workflows/` no longer verifies this
  claim on its own, which is the point of recording the relationship.
- Secret scanning + push protection: enabled
- gosec security scanning in CI with baseline drift detection (`scripts/gosec-compare.py`)
- `go vet` and race-detector-enabled tests in CI
- Scheduled weekly security workflow with auto-issue on failure
- **SLSA provenance attestation** on Docker images and GoReleaser binaries via `actions/attest-build-provenance`
- **SBOM generation** via syft in GoReleaser
- **Cosign keyless signing** on Docker images and checksum files via Sigstore (verify with `cosign verify`)

## Shared CI workflows

Part of this repository's CI is **defined in another repository** — [`4cloudguru/shared-workflows`](https://github.com/4cloudguru/shared-workflows) — and called from `.github/workflows/`. That is a real supply-chain relationship, and it is recorded here so an audit of this repository does not stop at this repository's own tree.

**What runs, and where it is pinned.** Each caller in `.github/workflows/` names the shared workflow on its `uses:` line, pinned to a full 40-hex commit SHA with a trailing comment naming the release that SHA is. The tag is a label; the SHA is what runs. An unlabelled SHA is rejected by the workflow-hardening gate, because a bare 40-hex ref cannot be reviewed or updated deliberately.

**Why the pins have to agree across repositories.** A shared definition drifts differently from a duplicated file: every repository looks like it is using "the shared one" while sitting on different commits, which is *harder* to see than divergent files, not easier. A signature in `security-orchestration` (`shared-workflow-pin-parity`) reports **disagreement** between callers of the same shared workflow — it reports disagreement rather than staleness, because a repository deliberately held back is a decision while N repositories disagreeing without anyone deciding is drift.

**What the shared repository is itself protected by.** Its `main` requires its own zizmor and actionlint checks with `enforce_admins` enabled, restricts which third-party actions may run to an explicit allowlist, issues a read-only default `GITHUB_TOKEN`, and runs the workflow-hardening gate against itself.

**What this repository still controls.** Triggers, concurrency, and the secrets it passes. Secrets are passed **by name** — never `secrets: inherit`, which would forward every secret in this repository to a workflow owned by someone else. Any `vars.*` a shared workflow reads resolve against **this** repository, so credentials and their installation scope do not move.
