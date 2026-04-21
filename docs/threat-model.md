# Threat Model — Terraform Registry

**Document version:** 1.0
**Last updated:** 2026-04-20
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

---

## 1. System Overview

The Terraform Registry is a self-hosted service that stores, indexes, and serves
Terraform modules and providers. It comprises:

- **Backend API server** (Go) — handles authentication, authorization, storage,
  module analysis, security scanning, and the Terraform registry protocol.
- **Frontend SPA** (React) — admin UI served by nginx.
- **PostgreSQL** — persistent metadata, user accounts, audit logs.
- **Object storage** (S3/Azure Blob/GCS/filesystem) — module and provider archives.
- **Redis** (optional) — rate-limit state, OIDC session cache.

## 2. Data Flow Diagram

```
┌───────────────────────────────────────────────────────────────────┐
│                       External Zone                               │
│                                                                   │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐  │
│  │Terraform │   │ Browser  │   │  CI/CD   │   │  IdP (OIDC/  │  │
│  │  CLI     │   │  User    │   │ Pipeline │   │  SAML/LDAP)  │  │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘   └──────┬───────┘  │
│       │              │              │                 │           │
└───────┼──────────────┼──────────────┼─────────────────┼───────────┘
        │              │              │                 │
   ─────┼──────────────┼──────────────┼─────────────────┼───── TLS boundary
        │              │              │                 │
┌───────┼──────────────┼──────────────┼─────────────────┼───────────┐
│       ▼              ▼              ▼                 ▼           │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                    Load Balancer / Ingress                  │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
│                             │                                     │
│         ┌───────────────────┼────────────────────┐                │
│         ▼                                        ▼                │
│  ┌──────────────┐                        ┌──────────────┐         │
│  │   Frontend   │                        │   Backend    │         │
│  │   (nginx)    │───── /api/* proxy ────▶│   (Go API)   │         │
│  └──────────────┘                        └──────┬───────┘         │
│                                                 │                 │
│                    ┌────────────────┬────────────┼────────┐       │
│                    ▼                ▼            ▼        ▼       │
│             ┌───────────┐  ┌──────────────┐ ┌───────┐ ┌──────┐   │
│             │PostgreSQL │  │Object Storage│ │ Redis │ │Scanner│  │
│             │           │  │(S3/Blob/GCS) │ │(opt.) │ │(opt.) │  │
│             └───────────┘  └──────────────┘ └───────┘ └──────┘   │
│                                                                   │
│                       Internal Zone                               │
└───────────────────────────────────────────────────────────────────┘
```

## 3. Trust Boundaries

| Boundary | Description                                                                                       |
| -------- | ------------------------------------------------------------------------------------------------- |
| **TB-1** | Internet → Load Balancer: TLS terminates here. All external traffic is encrypted in transit.      |
| **TB-2** | Load Balancer → Backend/Frontend pods: internal network. May use mTLS in zero-trust environments. |
| **TB-3** | Backend → PostgreSQL: credentials-authenticated connection, ideally TLS-encrypted.                |
| **TB-4** | Backend → Object Storage: IAM or credential-authenticated, TLS-encrypted.                         |
| **TB-5** | Backend → Redis: password-authenticated, optionally TLS-encrypted.                                |
| **TB-6** | Backend → External IdP: OIDC/SAML/LDAP over TLS.                                                  |
| **TB-7** | Backend → Scanner binary: local process invocation with constrained arguments.                    |

## 4. Assets

| Asset                    | Sensitivity | Description                                           |
| ------------------------ | ----------- | ----------------------------------------------------- |
| Module/provider archives | High        | Proprietary IaC code, may contain embedded secrets    |
| API keys (hashed)        | Critical    | bcrypt-hashed; compromise enables unauthorized access |
| OIDC/SAML secrets        | Critical    | Client secrets, signing keys                          |
| Encryption key           | Critical    | Encrypts API key hashes and sensitive config          |
| PostgreSQL credentials   | Critical    | Database access                                       |
| Audit logs               | High        | Compliance evidence; must be tamper-resistant         |
| User PII                 | Medium      | Email addresses, usernames, IdP identifiers           |
| Scanner findings         | High        | Vulnerability data about hosted modules               |

## 5. STRIDE Analysis

### 5.1 Spoofing (S)

| ID  | Threat                                                     | Component              | Mitigation                                                                                                                       | Status        |
| --- | ---------------------------------------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| S-1 | Attacker impersonates a legitimate user via stolen API key | Backend auth           | API keys are bcrypt-hashed (cost ≥12); keys have expiry dates; rate limiting on auth endpoints; audit logging of all auth events | ✅ Implemented |
| S-2 | Attacker forges OIDC/SAML tokens                           | Backend auth           | Token signature verification against IdP JWKS/metadata; issuer + audience validation; nonce/replay protection                    | ✅ Implemented |
| S-3 | Attacker performs LDAP injection to bypass auth            | Backend LDAP connector | Parameterized LDAP queries with input escaping; bind DN validation                                                               | ✅ Implemented |
| S-4 | Attacker hijacks session via XSS                           | Frontend               | httpOnly + Secure + SameSite=Strict cookies; CSP with nonces; no inline scripts                                                  | ✅ Implemented |
| S-5 | DNS spoofing redirects IdP callbacks                       | Backend OIDC           | Strict redirect_uri validation; state parameter CSRF protection                                                                  | ✅ Implemented |

### 5.2 Tampering (T)

| ID  | Threat                                                     | Component       | Mitigation                                                                                                         | Status                                       |
| --- | ---------------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| T-1 | Attacker modifies module archive in transit                | Network         | TLS on all connections; SHA-256 checksums verified on download                                                     | ✅ Implemented                                |
| T-2 | Attacker modifies module archive at rest in object storage | Storage         | Checksum verification on retrieval; storage bucket versioning recommended; cosign signatures on release artifacts  | ✅ Implemented                                |
| T-3 | SQL injection modifies database records                    | Backend API     | Parameterized queries throughout; no raw SQL string interpolation; sqlc/GORM with prepared statements              | ✅ Implemented                                |
| T-4 | Attacker tampers with audit logs                           | Audit system    | Append-only audit table; DB user has no DELETE/UPDATE on audit table; hash-chain export for integrity verification | ⚠️ Partial — hash-chain export planned (C3.3) |
| T-5 | Supply chain attack via compromised base image             | Container build | Pinned image digests; cosign signatures; SLSA L3 provenance; SBOM generation                                       | ✅ Implemented                                |
| T-6 | Malicious module upload with embedded malware              | Module pipeline | Security scanning (Trivy/Checkov) on upload; scanner version pinning; severity threshold blocking                  | ✅ Implemented                                |

### 5.3 Repudiation (R)

| ID  | Threat                                      | Component    | Mitigation                                                                                                                                      | Status                                |
| --- | ------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| R-1 | User denies performing a destructive action | Audit system | All API mutations logged with user ID, IP, timestamp, resource, and auth method; audit logs shipped to external SIEM                            | ✅ Implemented                         |
| R-2 | Admin denies modifying RBAC roles           | Audit system | Role/scope changes logged with before/after state in metadata field                                                                             | ✅ Implemented                         |
| R-3 | Attacker deletes audit logs to cover tracks | Audit system | DB-level protection (no DELETE grant); external shipper (syslog/webhook) creates independent copy; legal-hold API prevents cleanup job deletion | ⚠️ Partial — legal-hold planned (C3.3) |

### 5.4 Information Disclosure (I)

| ID  | Threat                                           | Component   | Mitigation                                                                                                                   | Status        |
| --- | ------------------------------------------------ | ----------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------- |
| I-1 | API key leaked in logs or error responses        | Backend     | API keys never logged in plaintext; error responses use generic messages; gosec scans for credential patterns                | ✅ Implemented |
| I-2 | Module source code exposed to unauthorized users | Backend API | Scope-based RBAC (modules:read); per-org access controls; download endpoints check auth                                      | ✅ Implemented |
| I-3 | Database credentials exposed via config dump     | Backend     | Encryption key encrypts sensitive config; env vars preferred over file for secrets; config endpoint redacts sensitive fields | ✅ Implemented |
| I-4 | Verbose error messages reveal internal topology  | Backend     | Production mode uses generic error messages; stack traces only in debug level; Swagger UI disabled by default in production  | ✅ Implemented |
| I-5 | Scanner findings exposed to non-admin users      | Backend API | Scanner endpoints require `admin` or `scanning:read` scope                                                                   | ✅ Implemented |
| I-6 | User PII enumeration via API                     | Backend API | User list endpoints require admin scope; user lookup by ID only (no email enumeration); rate limiting                        | ✅ Implemented |

### 5.5 Denial of Service (D)

| ID  | Threat                                         | Component          | Mitigation                                                                                              | Status                            |
| --- | ---------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------------------- | --------------------------------- |
| D-1 | API flooding exhausts backend resources        | Backend            | Per-principal rate limiting (token bucket); configurable per-org limits; 429 responses with Retry-After | ✅ Implemented                     |
| D-2 | Large file upload exhausts storage             | Backend API        | Upload size limits enforced; per-org quota system planned                                               | ⚠️ Partial — quotas planned (D3.4) |
| D-3 | Database connection exhaustion                 | Backend            | Connection pool with max limits; query timeouts; circuit breaker on DB errors                           | ✅ Implemented                     |
| D-4 | Scanner process consumes excessive CPU/memory  | Scanner job        | Worker count limits; per-scan timeout; subprocess resource limits                                       | ✅ Implemented                     |
| D-5 | Redis unavailability cascades to auth failures | Backend            | Graceful fallback to in-memory rate limiting; OIDC session state can recover from Redis loss            | ✅ Implemented                     |
| D-6 | Recursive module dependency download storm     | Pull-through cache | Cache layer prevents repeated upstream fetches; circuit breaker on upstream errors                      | ✅ Implemented                     |

### 5.6 Elevation of Privilege (E)

| ID  | Threat                                               | Component    | Mitigation                                                                                                                               | Status        |
| --- | ---------------------------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| E-1 | User escalates from read-only to admin               | Backend RBAC | Scope-based authorization on every endpoint; role templates are immutable after creation (admin audit); middleware enforces scope checks | ✅ Implemented |
| E-2 | SCIM token used beyond provisioning scope            | Backend SCIM | SCIM tokens have dedicated `scim:provision` scope; cannot access module/provider endpoints                                               | ✅ Implemented |
| E-3 | Container escape leads to host compromise            | Deployment   | Non-root container user; read-only root filesystem; dropped capabilities; seccomp/AppArmor profiles recommended in deployment docs       | ✅ Implemented |
| E-4 | SQL injection leads to privilege escalation          | Backend      | Parameterized queries; DB user has minimum required grants (no SUPERUSER); separate migration user for DDL                               | ✅ Implemented |
| E-5 | Path traversal in module/provider archive extraction | Backend      | Archive extraction validates paths; rejects entries with `..` components; temp directory isolation                                       | ✅ Implemented |

## 6. Assumptions

1. **TLS termination** is handled by the load balancer or ingress controller. The backend may optionally serve TLS directly but this is not required in typical deployments.
2. **PostgreSQL** is deployed in a private network not directly accessible from the internet.
3. **Object storage** access is controlled by IAM policies or service credentials, not public bucket ACLs.
4. **The encryption key** (`ENCRYPTION_KEY`) is managed securely — injected via secrets manager, not stored in version control.
5. **Container orchestration** (Kubernetes, ECS, etc.) provides network segmentation between services.
6. **Scanner binaries** are trusted — supply-chain integrity of the scanner itself is out of scope but version pinning mitigates stale/compromised binaries.

## 7. Residual Risks

| ID   | Risk                                                     | Likelihood | Impact   | Mitigation Plan                                                                                |
| ---- | -------------------------------------------------------- | ---------- | -------- | ---------------------------------------------------------------------------------------------- |
| RR-1 | Zero-day in Go standard library or dependencies          | Low        | High     | Dependabot + OSV nightly scan; SBOM enables rapid impact assessment                            |
| RR-2 | Compromised IdP pushes malicious group claims            | Low        | High     | Group→scope mapping limits blast radius; audit logging detects anomalies                       |
| RR-3 | Insider threat — admin with full access                  | Medium     | High     | Audit logging; require MFA for admin accounts (IdP-enforced); break-glass procedure documented |
| RR-4 | Object storage misconfiguration exposes archives         | Low        | Critical | Deployment docs mandate private buckets; health check verifies bucket ACL                      |
| RR-5 | Scanner bypass via crafted archive that evades detection | Medium     | Medium   | Defense in depth — upload approvals, policy engine (planned), multiple scanner support         |

## 8. Review Schedule

This threat model should be reviewed:

- On every major version release (x.0.0)
- When new authentication mechanisms are added
- When new data stores or external integrations are introduced
- At least annually, even if no significant changes occurred

## 9. References

- [SECURITY.md](../SECURITY.md) — vulnerability reporting policy
- [Architecture](architecture.md) — system architecture documentation
- [OWASP STRIDE](https://owasp.org/www-community/Threat_Modeling) — methodology reference
- [ADR-001: Scope-based RBAC](adr/001-scope-based-rbac.md)
- [ADR-004: JWT + API Key dual auth](adr/004-jwt-plus-apikey-dual-auth.md)
- [ADR-011: Password hashing](adr/0011-password-hashing.md)
