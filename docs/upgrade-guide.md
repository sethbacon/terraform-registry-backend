<!-- markdownlint-disable MD013 -->
# Version Upgrade Guide

This guide documents the upgrade process between Terraform Registry versions,
including breaking changes, migration behavior, rollback strategies, and
pre-flight validation.

## General Upgrade Procedure

### Pre-flight Checks

Before upgrading, run the preflight validation command:

```bash
# Binary
./terraform-registry upgrade preflight --config config.yaml

# Docker
docker run --rm \
  -v $(pwd)/config.yaml:/app/config.yaml \
  ghcr.io/sethbacon/terraform-registry-backend:NEW_VERSION \
  upgrade preflight --config /app/config.yaml
```

The preflight check validates:

- Database connectivity and current schema version
- Required schema migrations for the target version
- Storage backend accessibility
- Configuration compatibility (deprecated/removed settings)
- Available disk space for migration

### Standard Upgrade Steps

1. **Back up the database:**

   ```bash
   pg_dump -Fc terraform_registry > backup-$(date +%Y%m%d).dump
   ```

2. **Back up object storage** (if not using versioned buckets)

3. **Run preflight checks** (see above)

4. **Stop the current backend** (in rolling deployments, use a maintenance window for major upgrades)

5. **Deploy the new version:**
   - Docker: update image tag in compose/k8s manifests
   - Binary: replace the binary

6. **Start the backend** — migrations run automatically on startup

7. **Verify health:**

   ```bash
   curl -s https://registry.example.com/health | jq
   curl -s https://registry.example.com/version | jq
   ```

8. **Verify key functionality:**
   - Module listing: `terraform providers mirror`
   - Module download: `terraform init` in a consumer project
   - Admin UI login

### Rollback Strategy

If issues are found after upgrade:

1. **Stop the new version**
2. **Restore the database backup:**

   ```bash
   pg_restore -d terraform_registry backup-YYYYMMDD.dump
   ```

3. **Deploy the previous version**
4. **Verify functionality**

> **Important:** Some migrations are irreversible. See the per-version notes
> below and the [Migration Rollback Documentation](../backend/internal/db/migrations/README.md)
> for details on which migrations can be reversed.

---

## Version-Specific Upgrade Notes

> **Coverage.** Detailed notes exist for the upgrade paths listed below: the
> `0.6`–`0.10` series, the two major boundaries (`1.x → 2.0`, `2.x → 3.0`), and the
> most recent release. The intervening minor releases are **not** individually
> documented here — they introduced no breaking changes, which is why they were
> released as minors. For anything not listed, `CHANGELOG.md` is authoritative:
> every release is recorded there, and any breaking change appears under a
> `⚠ BREAKING CHANGES` heading.
>
> Concretely, across every release from `0.10.1` to `3.5.0` there are exactly **two**
> breaking changes, both captured below. Absence of a note for your specific version
> pair means there was nothing version-specific to do beyond the standard procedure
> above — not that the note is missing.

### 0.6.x → 0.7.0

**Breaking Changes:**

- Minimum PostgreSQL version raised to 14 (was 12)
- `TFR_AUTH_SECRET` environment variable renamed to `ENCRYPTION_KEY`
- API key format changed from UUID to prefixed format (`tfr_...`)

**Migrations:**

- `000020_search_indexes` — adds full-text search indexes (may take several minutes on large databases)
- `000021_setup_scanning` — adds scanning configuration tables
- `000022_storage_migration` — adds storage migration state tracking
- `000023_audit_retention` — adds audit log retention configuration

**Pre-flight:**

```bash
./terraform-registry upgrade preflight --config config.yaml
```

**Rollback:** Migrations 000020–000023 are all reversible. Run `migrate down` to version 19 before deploying 0.6.x.

### 0.7.x → 0.8.0

**Breaking Changes:**

- OIDC configuration moved from flat fields to nested structure in `config.yaml`
- Deprecated `auth.oidc_issuer_url` — use `auth.oidc.issuer_url` instead
- Redis is now required for multi-pod deployments (rate limiting + session state)

**Migrations:**

- `000024_module_deprecation` — adds deprecation fields to module_versions
- `000025_org_idp_binding` — adds per-org IdP binding support

**New Features Requiring Configuration:**

- SAML 2.0: configure in `auth.saml` section
- LDAP: configure in `auth.ldap` section
- SCIM: enable in `auth.scim.enabled: true`

**Pre-flight:**

```bash
./terraform-registry upgrade preflight --config config.yaml
```

**Rollback:** Migrations 000024–000025 are reversible. Note: SAML/LDAP user records created during 0.8.0 operation will be orphaned on rollback.

### 0.8.x → 0.9.0

**Breaking Changes:**

- None expected

**Migrations:**

- `000026_org_quotas` — adds per-org quota tables

> Note: Legal hold for audit logs is implemented in application code
> (`backend/internal/audit/legal_hold.go`), not via a dedicated migration.

**Pre-flight:**

```bash
./terraform-registry upgrade preflight --config config.yaml
```

### 0.9.x → 0.10.0

**Breaking Changes:**

- Audit log cleanup job now respects legal holds. Ensure any active investigations have holds in place before upgrading.

**New Features:**

- GDPR data-subject export/erasure endpoints
- OCSF audit log export format
- Air-gap installation support (`make airgap-bundle`)

**Pre-flight:**

```bash
./terraform-registry upgrade preflight --config config.yaml
```

### 0.18.x → 1.0.0

**No breaking changes.** 1.0.0 was a version marker (released via `Release-As: 1.0.0`
in #316) signalling API stability, not a change in behaviour. Upgrade using the
standard procedure.

### 1.x → 2.0.0

**Breaking Changes:**

- Feature-table foreign keys are repointed from `public.{users,organizations}` to
  `identity.{users,organizations}` (#451). This **drops and recreates 22 constraints**.

**Applies to:** deployments that have completed the identity-schema cutover. On
non-cutover deployments the migration is a **no-op**.

**Migrations:**

- `000038_feature_fk_to_identity` — the FK repoint described above.

**Pre-flight:** run the preflight check, and on a large database expect the constraint
recreation to hold locks briefly — schedule accordingly rather than during peak write
traffic.

**Rollback:** `000038` is reversible.

### 2.x → 3.0.0

**Breaking Changes:**

- Adopts `terraform-suite-identity` v0.17.0 (#614), which brings three
  behaviour changes worth checking before deploying:
  - **`email_verified` is now enforced** on IdP logins. Users whose IdP does not
    assert `email_verified` (or asserts `false`) will be refused. Verify your IdP
    emits this claim before upgrading, or you can lock out your own users.
  - **`ClientSecretCiphertext`** changes how SSO client secrets are stored.
  - **`ScopeAdmin` guard** tightens which callers may grant the admin scope.

**Also in 3.0.0** (not breaking, but security-relevant): OIDC/Azure AD logins are now
bound with a nonce and PKCE (#612), and `/organizations/:id*` routes enforce
per-organization membership (#611) — if you have automation using a token that held
`organizations:write` via one organization to act on another, it will now receive 403.

**Migrations:** none specific to the identity adoption.

**Rollback:** code-only; rolling back the binary restores the previous behaviour.

### 3.5.x → 3.6.0

The exact version is whatever release first contains PRs #712 and #724 — confirm
against `CHANGELOG.md`. Both entries below are **behavior changes that activate on
upgrade with no configuration change**, so review them before deploying.

**Audit configuration becomes active (#659, PR #712):**

`audit.log_read_operations`, `audit.log_failed_requests` and `audit.shippers` were
previously parsed and validated but **never actually used** — the audit middleware
was wired with hardcoded `nil`s. That was the bug; those settings are now honored.

If you already have any of them set, upgrading changes runtime behavior immediately:

- `log_read_operations: true` — GET/read-path audit rows begin being written. On a
  busy registry this can change audit table growth rate sharply; check retention and
  disk headroom first.
- `log_failed_requests: true` — failed-request rows begin being written.
- `shippers: [...]` — a configured external shipper **starts receiving traffic**. The
  registry begins making outbound calls to an endpoint that has never received them,
  which may be unexpected volume for a webhook/SIEM target.

**Recommended:** review your `audit.*` block before upgrading and comment out anything
you did not intend to be live. To keep the previous effective behavior, unset these keys.

**Audit log reads are scoped to the caller's organizations (#719, PR #724):**

`GET /api/v1/admin/audit-logs` previously returned **every organization's** audit trail
to any holder of `audit:read`. Because `audit:read` is granted per-organization by the
`auditor` role template but arrives in the session token as part of a flat, org-less
scope union, that crossed the tenant boundary.

After upgrade:

- Platform admins (the `admin` wildcard scope) still see all organizations.
- A non-admin auditor sees only the organizations they belong to.
- A caller belonging to **multiple** organizations must now pass `organization_id`
  explicitly; without it the request returns `400` rather than a silently partial result.

**Action required** if you have tooling, dashboards, or exports that read this endpoint
with a non-admin token and expect estate-wide results: either grant that principal the
`admin` scope deliberately, or update the caller to iterate per organization.

**Credential invalidation on authority reduction (#732, #736):**

Reducing a principal's authority now invalidates the credentials that carry a
*snapshot* of it. Previously only JWT sessions were swept, and only at some events;
API keys were never swept at all, because an API key's scopes **and** its owning
`organization_id` are frozen on the `api_keys` row at creation and are read straight
back out by the auth middleware. An offboarded member kept a working
`modules:write` / `providers:write` credential into the organization's namespaces
indefinitely.

These sweeps **activate on upgrade with no configuration change**, and they DELETE
API keys. An API key's secret is displayed once at creation and cannot be recovered:
a deleted key must be re-issued and re-distributed to whatever consumes it (CI
pipelines, Terraform `credentials` blocks, automation). Review the list below against
your own automation before upgrading.

Events that now delete a principal's organization-bound API keys:

- Removal from an organization (`DELETE /api/v1/organizations/:id/members/:user_id`).
- A member's role-template reassignment (`PUT .../members/:user_id`) — **only** when
  the new template grants strictly less; a promotion deletes nothing.
- A role template's scopes being **narrowed**, or the template being deleted. Adding
  scopes, or merely reordering the list, sweeps nothing.
- IdP group-mapping deprovisioning at OIDC/SAML/LDAP login.
- User deletion (`DELETE /api/v1/users/:id`) and GDPR erasure
  (`POST /api/v1/admin/users/:id/erase`).

Only keys asking for **more than the principal retains** are deleted; a key entirely
within the remaining authority survives. Scope comparison honors the `admin` wildcard
and the read/write implications, and is order-insensitive.

**SCIM deactivation now destroys credentials.** `DELETE /scim/v2/Users/{id}`, and a
PUT or PATCH setting `active: false`, now revoke the user's sessions and delete
**every** API key they hold in **every** organization — not just their memberships.
If your IdP deactivates and later reactivates users (a common lifecycle for
contractors or leave-of-absence), reactivation restores memberships but **cannot**
restore API keys; they must be re-issued.

> **SCIM PUT semantics changed with this.** `active` is now optional: a PUT that
> **omits** it leaves the user's authority untouched, where previously an omitted
> `active` was indistinguishable from `active: false` and silently deprovisioned the
> user. If you have an IdP or script relying on a partial PUT to deactivate users,
> it must now send `"active": false` explicitly.

Responses from these endpoints may carry `revocation_incomplete: true`. The authority
change itself succeeded, but part of the credential sweep did not — treat it as an
open incident and re-run the action.

**Also in this change:** an organization-bound API key is re-verified at the point of
use. A key whose owner has left the organization, or whose role template no longer
grants the required scope, is now rejected (`403`) on namespace mutations even if some
lifecycle path failed to sweep it. Long-lived keys belonging to users who have since
been offboarded or downgraded will begin failing on upgrade — that is the intended
correction, but audit for it before deploying if you have service automation running
under a personal key.

**Migrations:** none for any change in this section.

**Rollback:** all are code-only; rolling back the binary restores the previous
behavior. Note that API keys deleted by a sweep are **not** restored by a rollback.

---

## Upgrade Preflight CLI Reference

```text
Usage: terraform-registry upgrade preflight [flags]

Flags:
  --config string     Path to config.yaml (overrides CONFIG_PATH; falls back to environment variables)
  --verbose           Show the detail message for every check, not just warnings/failures

Examples:
  terraform-registry upgrade preflight
  terraform-registry upgrade preflight --config config.yaml --verbose
```

The current/target versions and the pending-migration set are derived
automatically: the current schema version is read from `schema_migrations`, and
the target version is the binary's own build version. The command validates
state and reports readiness; it never applies migrations (those run on the next
`serve` startup), so there is no separate dry-run mode.

### Preflight Check Output

```text
Terraform Registry — Upgrade Preflight
=======================================
Binary version:   1.0.0
Build date:       2026-04-29T00:00:00Z

  ✓ Configuration
  ✓ Database: Connected (PostgreSQL 16.2 ...)
  ✓ PostgreSQL version: Version 16.x
  ✓ Schema: Current schema version: 40
  ✓ Encryption key: Present
  ✓ Storage backend: Type: s3
  ⚠ Redis: Not configured — required for multi-pod deployments

Result: READY TO UPGRADE (with warnings)
```

---

## Skip-Version Upgrades

Sequential upgrades (0.7 → 0.8 → 0.9) are recommended. Skip-version upgrades
(0.7 → 0.9) are supported because migrations are applied incrementally, but:

- Read **all** intermediate version notes for breaking changes
- Run preflight with `--from` and `--to` to validate the full migration chain
- Test in a staging environment first

---

## References

- [Disaster Recovery](disaster-recovery.md) — backup and restore procedures
- [Migration Rollback Documentation](../backend/internal/db/migrations/README.md)
- [Configuration Reference](configuration.md)
- [Deployment Guide](deployment.md)
