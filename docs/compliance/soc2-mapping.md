# SOC 2 Type II Control Mapping

This document maps SOC 2 Trust Service Criteria to Terraform Registry features,
configurations, and evidence sources. It is intended to assist compliance teams
during SOC 2 Type II audits.

**Last updated:** 2026-04-20
**Applicable version:** 0.10.0+

---

## CC1 — Control Environment

| Criteria | Control                                    | Registry Feature                               | Evidence Source                                            |
| -------- | ------------------------------------------ | ---------------------------------------------- | ---------------------------------------------------------- |
| CC1.1    | Commitment to integrity and ethical values | Code of Conduct, Contributing guidelines       | `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`                    |
| CC1.2    | Board/management oversight                 | CODEOWNERS-enforced PR reviews                 | `.github/CODEOWNERS`, PR review logs                       |
| CC1.3    | Organizational structure and authority     | Role-based access control (RBAC) with scopes   | `backend/internal/auth/scopes.go`, role-template admin API |
| CC1.4    | Commitment to competence                   | CI/CD pipeline with lint, test, security gates | `.github/workflows/ci.yml`, PR check requirements          |
| CC1.5    | Accountability for internal controls       | Audit logging of all security-relevant events  | `backend/internal/audit/`, audit log export API            |

## CC2 — Communication and Information

| Criteria | Control                                    | Registry Feature                          | Evidence Source                                       |
| -------- | ------------------------------------------ | ----------------------------------------- | ----------------------------------------------------- |
| CC2.1    | Internal communication of objectives       | Architecture docs, ADRs, roadmap          | `docs/architecture.md`, `docs/adr/*.md`, `ROADMAP.md` |
| CC2.2    | Internal communication of responsibilities | CODEOWNERS, contributing guide            | `.github/CODEOWNERS`, `CONTRIBUTING.md`               |
| CC2.3    | External communication                     | Security policy, vulnerability disclosure | `SECURITY.md`, GitHub Security Advisories             |

## CC3 — Risk Assessment

| Criteria | Control                            | Registry Feature                              | Evidence Source                               |
| -------- | ---------------------------------- | --------------------------------------------- | --------------------------------------------- |
| CC3.1    | Risk identification                | STRIDE threat model                           | `docs/threat-model.md`                        |
| CC3.2    | Fraud risk assessment              | Audit logging, RBAC, API key expiry           | Audit logs, `backend/internal/auth/`          |
| CC3.3    | Change-related risk identification | PR-based workflow, required reviews, CI gates | Branch protection rules, CI logs              |
| CC3.4    | Risk mitigation                    | Security scanning, dependency review, SBOM    | `gosec`, Trivy, Dependabot, `.goreleaser.yml` |

## CC4 — Monitoring Activities

| Criteria | Control                               | Registry Feature                                         | Evidence Source                                                       |
| -------- | ------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------- |
| CC4.1    | Ongoing monitoring                    | Prometheus metrics, audit log shipping, health endpoints | `/metrics`, `/health`, audit shipper config                           |
| CC4.2    | Deficiency evaluation and remediation | gosec baseline drift detection, dependency review        | `backend/scripts/gosec-compare.py`, `.github/workflows/pr-checks.yml` |

## CC5 — Control Activities

| Criteria | Control                       | Registry Feature                                         | Evidence Source                                                       |
| -------- | ----------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------- |
| CC5.1    | Risk-mitigating controls      | Rate limiting, input validation, parameterized queries   | `backend/internal/middleware/ratelimit.go`, API handlers              |
| CC5.2    | Technology controls           | TLS, encryption at rest (encryption key), bcrypt hashing | Config, `backend/internal/crypto/`, `backend/internal/auth/apikey.go` |
| CC5.3    | Policy and procedure controls | CONTRIBUTING.md, release process, CLAUDE.md              | Repository documentation                                              |

## CC6 — Logical and Physical Access Controls

| Criteria | Control                              | Registry Feature                                                              | Evidence Source                                                       |
| -------- | ------------------------------------ | ----------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| CC6.1    | Logical access security              | OIDC/SAML/LDAP/API key authentication                                         | `backend/internal/auth/`                                              |
| CC6.2    | User provisioning/deprovisioning     | SCIM 2.0 provisioning, JIT deprovisioning                                     | `backend/internal/api/scim/`                                          |
| CC6.3    | Registration and authorization       | Role templates with scoped permissions                                        | `backend/internal/auth/scopes.go`, admin role API                     |
| CC6.4    | Access restriction management        | Per-endpoint scope enforcement, mTLS option                                   | Middleware auth checks, `backend/internal/auth/mtls/`                 |
| CC6.5    | Authentication credential management | bcrypt cost ≥12, API key rotation/expiry, OIDC refresh rotation               | `docs/adr/0011-password-hashing.md`, auth config                      |
| CC6.6    | Access removal                       | SCIM deprovisioning, API key revocation, JWT revocation table                 | SCIM API, admin user/key endpoints, `000013_jwt_revocation` migration |
| CC6.7    | Data transmission security           | TLS for all connections, mTLS option                                          | Server TLS config, nginx TLS, DB TLS option                           |
| CC6.8    | Encryption of data at rest           | Encryption key for sensitive fields, storage encryption delegated to provider | `ENCRYPTION_KEY`, S3 SSE / Azure SSE / GCS CMEK                       |

## CC7 — System Operations

| Criteria | Control                   | Registry Feature                                            | Evidence Source                     |
| -------- | ------------------------- | ----------------------------------------------------------- | ----------------------------------- |
| CC7.1    | Infrastructure management | Container orchestration (K8s/ECS), IaC deployment examples  | `deployments/` directory            |
| CC7.2    | Change management         | Git-based PR workflow, CI gates, required reviews           | Branch protection, CI workflows     |
| CC7.3    | Configuration management  | Viper-based config with env var override, config validation | `backend/internal/config/config.go` |
| CC7.4    | Security event detection  | Audit logging, rate-limit breach metrics, scanner findings  | Audit shipper, Prometheus metrics   |
| CC7.5    | Incident response         | Security policy with response timelines                     | `SECURITY.md`                       |

## CC8 — Change Management

| Criteria | Control              | Registry Feature                             | Evidence Source                         |
| -------- | -------------------- | -------------------------------------------- | --------------------------------------- |
| CC8.1    | Change authorization | PR required, CODEOWNERS review, CI must pass | `.github/CODEOWNERS`, branch protection |

## CC9 — Risk Mitigation

| Criteria | Control                | Registry Feature                                     | Evidence Source                                      |
| -------- | ---------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| CC9.1    | Vendor risk management | Pinned dependencies, SBOM, dependency review         | `go.mod`, `.goreleaser.yml`, Dependabot              |
| CC9.2    | Business continuity    | DR documentation, backup procedures, upgrade runbook | `docs/disaster-recovery.md`, `docs/upgrade-guide.md` |

---

## Additional Trust Service Categories

### Availability (A1)

| Criteria | Control                   | Registry Feature                                       | Evidence Source                                    |
| -------- | ------------------------- | ------------------------------------------------------ | -------------------------------------------------- |
| A1.1     | Recovery objectives       | Documented RPO/RTO targets per tier                    | `docs/disaster-recovery.md`                        |
| A1.2     | Environmental protections | Container resource limits, health checks, auto-restart | Deployment manifests, health endpoint              |
| A1.3     | Recovery testing          | DR drill runbook and automation script                 | `docs/disaster-recovery.md`, `scripts/dr-drill.sh` |

### Confidentiality (C1)

| Criteria | Control                                    | Registry Feature                                               | Evidence Source                        |
| -------- | ------------------------------------------ | -------------------------------------------------------------- | -------------------------------------- |
| C1.1     | Identification of confidential information | Module archives, API keys, user PII classified in threat model | `docs/threat-model.md`                 |
| C1.2     | Disposal of confidential information       | GDPR erasure endpoint (tombstone), audit log retention job     | User erase API, audit retention config |

### Processing Integrity (PI1)

| Criteria | Control             | Registry Feature                                  | Evidence Source                            |
| -------- | ------------------- | ------------------------------------------------- | ------------------------------------------ |
| PI1.1    | Processing accuracy | SHA-256 checksum verification on all artifacts    | `backend/pkg/checksum/`, download handlers |
| PI1.2    | Error handling      | Structured error responses, validation middleware | API response types, validation package     |

### Privacy (P1–P8)

| Criteria | Control               | Registry Feature                                     | Evidence Source                                      |
| -------- | --------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| P1.1     | Privacy notice        | Privacy policy documentation                         | `PRIVACY.md` (frontend)                              |
| P3.1     | Collection limitation | Minimal PII collection (email, username from IdP)    | Auth handlers, user model                            |
| P4.1     | Use limitation        | PII used only for auth/audit; not shared externally  | Audit shipper config (self-hosted destinations only) |
| P6.1     | Data subject access   | User data export endpoint                            | `/admin/users/:id/export`                            |
| P8.1     | Data quality          | IdP-sourced attributes; SCIM sync keeps data current | SCIM provisioning                                    |

---

## Audit Evidence Collection

For SOC 2 audits, the following evidence should be collected:

1. **Access control evidence:** Export of role templates, user→role assignments, API key inventory
2. **Change management evidence:** Git log of merged PRs with review approvals
3. **Monitoring evidence:** Prometheus metrics snapshots, audit log exports (NDJSON or OCSF)
4. **Incident response evidence:** GitHub Security Advisory history, `SECURITY.md` review log
5. **Availability evidence:** DR drill log from `scripts/dr-drill.sh`, uptime metrics
6. **Cryptographic evidence:** cosign verification output, GitHub Artifact Attestations verification (`gh attestation verify`)
