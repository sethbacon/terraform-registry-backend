# ISO 27001:2022 Control Mapping

This document maps ISO 27001:2022 Annex A controls to Terraform Registry
features, configurations, and evidence sources. It supports organizations
seeking ISO 27001 certification that include the registry in their ISMS scope.

**Last updated:** 2026-04-20
**Applicable version:** 0.10.0+

---

## A.5 — Organizational Controls

| Control | Title                                      | Registry Feature                                               | Evidence Source                                         |
| ------- | ------------------------------------------ | -------------------------------------------------------------- | ------------------------------------------------------- |
| A.5.1   | Policies for information security          | Security policy, threat model                                  | `SECURITY.md`, `docs/threat-model.md`                   |
| A.5.2   | Information security roles                 | CODEOWNERS, RBAC scopes                                        | `.github/CODEOWNERS`, `backend/internal/auth/scopes.go` |
| A.5.3   | Segregation of duties                      | Separate scopes for read/write/admin; SCIM has dedicated scope | Role templates, scope enforcement                       |
| A.5.7   | Threat intelligence                        | Dependabot alerts, OSV scanner, gosec baseline                 | `.github/dependabot.yml`, CI workflows                  |
| A.5.8   | Information security in project management | Roadmap with security phases, ADRs for security decisions      | `ROADMAP.md`, `docs/adr/*.md`                           |
| A.5.9   | Inventory of information assets            | Asset classification in threat model                           | `docs/threat-model.md` §4                               |
| A.5.10  | Acceptable use                             | Code of Conduct, Contributing guide                            | `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`                 |
| A.5.14  | Information transfer                       | TLS for all connections; audit log shipping over TLS           | Server config, audit shipper config                     |
| A.5.23  | Information security for cloud services    | Cloud deployment guides with security recommendations          | `docs/deployment/*.md`                                  |
| A.5.24  | Incident management planning               | Security policy with response timelines                        | `SECURITY.md`                                           |
| A.5.25  | Assessment of information security events  | Audit logging, scanner findings, rate-limit metrics            | Audit logs, Prometheus metrics                          |
| A.5.26  | Response to incidents                      | Coordinated disclosure policy, CVE acknowledgment SLAs         | `SECURITY.md`                                           |
| A.5.28  | Collection of evidence                     | Audit log export (NDJSON/OCSF), legal hold API                 | Audit export endpoint, legal-hold API                   |
| A.5.29  | Information security during disruption     | DR documentation, backup procedures                            | `docs/disaster-recovery.md`                             |
| A.5.30  | ICT readiness for business continuity      | DR drill runbook with RPO/RTO targets                          | `docs/disaster-recovery.md`, `scripts/dr-drill.sh`      |
| A.5.33  | Protection of records                      | Audit log retention policy, append-only protection             | Audit retention config, DB grants                       |
| A.5.34  | Privacy and PII protection                 | GDPR tooling (export/erase), minimal collection                | User export/erase API endpoints                         |
| A.5.36  | Compliance with policies                   | CI gates enforce coding standards, security scans              | CI workflows, PR checks                                 |

## A.6 — People Controls

| Control | Title                              | Registry Feature                        | Evidence Source                |
| ------- | ---------------------------------- | --------------------------------------- | ------------------------------ |
| A.6.1   | Screening                          | N/A — organizational responsibility     | —                              |
| A.6.2   | Terms and conditions               | Contributing agreement                  | `CONTRIBUTING.md`              |
| A.6.5   | Responsibilities after termination | SCIM deprovisioning, API key revocation | SCIM API, admin key management |

## A.7 — Physical Controls

Physical controls are the responsibility of the hosting environment (cloud
provider or data center operator). The registry runs as a containerized
application with no physical infrastructure requirements.

## A.8 — Technological Controls

| Control | Title                                   | Registry Feature                                                  | Evidence Source                                    |
| ------- | --------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------- |
| A.8.1   | User endpoint devices                   | N/A — server-side application                                     | —                                                  |
| A.8.2   | Privileged access rights                | Admin scope enforcement, per-endpoint authorization               | Middleware auth, scope checks                      |
| A.8.3   | Information access restriction          | RBAC with per-resource scopes, org-scoped data isolation          | Role templates, org middleware                     |
| A.8.4   | Access to source code                   | GitHub repository access controls                                 | Repository settings                                |
| A.8.5   | Secure authentication                   | OIDC/SAML/LDAP/mTLS, bcrypt hashing, MFA (IdP-enforced)           | Auth packages, `docs/adr/0011-password-hashing.md` |
| A.8.6   | Capacity management                     | Per-org quotas, resource limit configuration                      | Quota system, deployment manifests                 |
| A.8.7   | Protection against malware              | Module security scanning (Trivy/Checkov), scanner version pinning | Scanning config, scanner job                       |
| A.8.8   | Management of technical vulnerabilities | Dependabot, OSV scanner, gosec, Trivy image scan                  | CI workflows, scheduled scans                      |
| A.8.9   | Configuration management                | Viper-based config with validation, env var layering              | `backend/internal/config/`                         |
| A.8.10  | Information deletion                    | GDPR erasure endpoint, audit retention cleanup                    | User erase API, retention job                      |
| A.8.11  | Data masking                            | Sensitive config fields redacted in API responses                 | Config endpoint, error handlers                    |
| A.8.12  | Data leakage prevention                 | No external CDN dependencies, gosec credential scanning           | Air-gap support, gosec rules                       |
| A.8.15  | Logging                                 | Structured audit logging to multiple destinations                 | `backend/internal/audit/shipper.go`                |
| A.8.16  | Monitoring activities                   | Prometheus metrics, health endpoints, alert rules                 | `/metrics`, `/health`, Grafana dashboards          |
| A.8.20  | Networks security                       | TLS on all connections, optional mTLS                             | Server TLS config, mTLS package                    |
| A.8.24  | Use of cryptography                     | TLS 1.2+, AES encryption at rest, bcrypt, cosign signing          | Crypto config, FIPS build variant                  |
| A.8.25  | Secure development lifecycle            | CI/CD with lint, test, SAST, SCA, SBOM, signed releases           | CI workflows, `.goreleaser.yml`                    |
| A.8.26  | Application security requirements       | Input validation, parameterized queries, CSRF protection          | Validation package, middleware                     |
| A.8.27  | Secure system architecture              | Architecture documentation, ADRs                                  | `docs/architecture.md`, `docs/adr/`                |
| A.8.28  | Secure coding                           | gosec static analysis, linting, code review                       | CI workflows, CODEOWNERS                           |
| A.8.29  | Security testing                        | Unit tests, integration tests, E2E tests, fuzz tests (planned)    | Test suites, CI workflows                          |
| A.8.31  | Separation of environments              | Separate compose files for dev/test/prod; env var config          | `deployments/docker-compose*.yml`                  |
| A.8.32  | Change management                       | Git-based PR workflow, required reviews, CI gates                 | Branch protection, CI                              |
| A.8.33  | Test information                        | Test fixtures use synthetic data only                             | Test files                                         |
| A.8.34  | Protection during audit testing         | Audit system not disruptable via API; append-only                 | DB grants, audit architecture                      |

---

## Statement of Applicability Notes

Controls marked N/A are not applicable because:
- **A.6.1 (Screening):** Organizational HR responsibility, not application-level.
- **A.7.x (Physical controls):** Application runs in cloud/container environments; physical security is the provider's responsibility.
- **A.8.1 (Endpoint devices):** Server-side application; end-user device management is organizational responsibility.

---

## Audit Evidence Collection

For ISO 27001 audits, evidence can be gathered from:

1. **Documentation:** All files in `docs/`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`
2. **Technical controls:** CI workflow run logs, branch protection settings, Dependabot alert history
3. **Access control:** Role template exports, SCIM provisioning logs, audit log filtered by auth events
4. **Monitoring:** Prometheus metric snapshots, Grafana dashboard screenshots, audit log exports
5. **Incident response:** GitHub Security Advisory history, `SECURITY.md` acknowledgment timeline compliance
6. **Continuity:** DR drill execution logs from `scripts/dr-drill.sh`
7. **Cryptographic:** cosign verification output, SLSA provenance verification, FIPS build attestation
