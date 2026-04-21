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
  ghcr.io/terraform-registry/backend:NEW_VERSION \
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
   curl -s https://registry.example.com/api/v1/version | jq
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
./terraform-registry upgrade preflight --from 0.6 --to 0.7
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
./terraform-registry upgrade preflight --from 0.7 --to 0.8
```

**Rollback:** Migrations 000024–000025 are reversible. Note: SAML/LDAP user records created during 0.8.0 operation will be orphaned on rollback.

### 0.8.x → 0.9.0

**Breaking Changes:**
- None expected

**Migrations:**
- Per-org quota tables
- Legal hold table for audit logs

**Pre-flight:**
```bash
./terraform-registry upgrade preflight --from 0.8 --to 0.9
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
./terraform-registry upgrade preflight --from 0.9 --to 0.10
```

---

## Upgrade Preflight CLI Reference

```
Usage: terraform-registry upgrade preflight [flags]

Flags:
  --config string     Path to config.yaml (default "config.yaml")
  --from string       Current version (auto-detected from DB if omitted)
  --to string         Target version (auto-detected from binary if omitted)
  --verbose           Show detailed migration plan
  --dry-run           Validate only, do not apply any changes

Examples:
  terraform-registry upgrade preflight
  terraform-registry upgrade preflight --from 0.7 --to 0.8 --verbose
```

### Preflight Check Output

```
Terraform Registry — Upgrade Preflight
=======================================
Current version:  0.7.2
Target version:   0.8.0
Database:         connected (PostgreSQL 16.2)
Schema version:   23
Target schema:    25

Pending migrations:
  000024_module_deprecation.up.sql  [reversible]
  000025_org_idp_binding.up.sql     [reversible]

Configuration checks:
  ✓ Database connectivity
  ✓ Storage backend accessible
  ✓ Encryption key present
  ⚠ Deprecated config: auth.oidc_issuer_url → use auth.oidc.issuer_url
  ✓ Redis connectivity (required for multi-pod)

Result: READY TO UPGRADE (1 warning)
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
