<!-- markdownlint-disable MD013 MD060 -->
# Database Migration Reference

This document catalogs all database migrations, their reversibility, and rollback procedures.

## Migration Index

| #      | Name                                   | Reversible    | Notes                                                     |
| ------ | -------------------------------------- | ------------- | --------------------------------------------------------- |
| 000001 | `initial_schema`                       | ⚠️ Destructive | Drops all tables — only safe on empty database            |
| 000002 | `api_key_expiry_notifications`         | ✅ Yes         | Drops added columns                                       |
| 000003 | `setup_wizard`                         | ✅ Yes         | Drops setup tables                                        |
| 000004 | `terraform_binary_mirror`              | ✅ Yes         | Drops binary mirror tables                                |
| 000005 | `terraform_mirror_version_filter`      | ✅ Yes         | Drops filter column                                       |
| 000006 | `terraform_mirror_stable_only`         | ✅ Yes         | Drops stable-only column                                  |
| 000007 | `binary_platform_download_count`       | ✅ Yes         | Drops download count column                               |
| 000008 | `scm_webhook_secret_nullable`          | ✅ Yes         | Re-applies NOT NULL constraint                            |
| 000009 | `module_versions_scm_repo_fk_set_null` | ✅ Yes         | Restores original FK behavior                             |
| 000010 | `provider_platforms_h1_hash`           | ✅ Yes         | Drops h1 hash column                                      |
| 000011 | `provider_version_shasums`             | ✅ Yes         | Drops shasums columns                                     |
| 000012 | `provider_version_docs`                | ✅ Yes         | Drops docs table                                          |
| 000013 | `jwt_revocation`                       | ✅ Yes         | Drops revocation table                                    |
| 000014 | `terraform_mirror_gpg_config`          | ✅ Yes         | Drops GPG config columns                                  |
| 000015 | `pull_through_cache`                   | ✅ Yes         | Drops pull-through tables                                 |
| 000016 | `module_version_scans`                 | ✅ Yes         | Drops scan results table                                  |
| 000017 | `module_version_docs`                  | ✅ Yes         | Drops module docs table                                   |
| 000018 | `add_scanning_read_scope`              | ✅ Yes         | Removes scope from defaults                               |
| 000019 | `webhook_retry`                        | ✅ Yes         | Drops retry columns                                       |
| 000020 | `search_indexes`                       | ✅ Yes         | Drops indexes (data preserved)                            |
| 000021 | `setup_scanning`                       | ✅ Yes         | Drops scanning setup columns                              |
| 000022 | `storage_migration`                    | ✅ Yes         | Drops migration state table                               |
| 000023 | `audit_retention`                      | ✅ Yes         | Drops retention config                                    |
| 000024 | `module_deprecation`                   | ✅ Yes         | Drops deprecation columns; existing deprecation data lost |
| 000025 | `org_idp_binding`                      | ✅ Yes         | Drops IdP binding columns; IdP associations lost          |
| 000026 | `org_quotas`                           | ✅ Yes         | Drops quota tables; quota config and usage data lost      |
| 000027 | `setup_ldap`                           | ✅ Yes         | Drops LDAP setup columns from `system_settings`           |
| 000028 | `module_version_replacement_source`    | ✅ Yes         | Drops replacement-source column                           |
| 000029 | `webhook_approval_tokens`              | ✅ Yes         | Drops the approval-tokens table                           |
| 000030 | `scan_execution_log`                   | ✅ Yes         | Drops scan execution-log column                           |
| 000031 | `backfill_scanner_name`                | ⚠️ No-op down  | Data backfill; the down migration cannot meaningfully revert it |
| 000032 | `cve_advisories`                       | ✅ Yes         | Drops the CVE advisory tables                             |
| 000033 | `ui_theme_config`                      | ✅ Yes         | Drops the UI theme config table                           |
| 000034 | `terraform_version_signature_storage`  | ✅ Yes         | Drops Terraform-version signature storage-key columns     |
| 000035 | `provider_version_signature_storage`   | ✅ Yes         | Drops provider-version signature storage-key columns      |
| 000036 | `releases_gpg_keys`                    | ✅ Yes         | Drops the cached upstream-key table; cache is rebuilt on next refresh tick |
| 000037 | `version_approval`                      | ✅ Yes         | Drops approval columns/indexes and the `version_approval_events` table; approval state lost |
| 000038 | `feature_fk_to_identity`               | ✅ Yes         | Reverts feature-table FKs to `public.{users,organizations}`; no-op when the `identity` schema is absent |
| 000039 | `add_packer_sentinel_opa_tools`        | ⚠️ Conditional | Restores the original tool CHECK constraint; the down fails if rows use `packer`/`sentinel`/`opa` |
| 000040 | `terraform_mirror_default_stable_approval` | ✅ Yes     | Reverts column defaults; existing rows are not modified   |
| 000041 | `scm_shared_app_credentials`           | ⚠️ Conditional | Drops app-credential columns; the down fails while providers still use an app auth mode |
| 000042 | `add_terraform_docs_tool`              | ⚠️ Conditional | Restores the tool CHECK constraint; the down fails if rows use `terraform-docs` |
| 000043 | `setup_notifications`                  | ✅ Yes         | Drops notification-config columns; persisted SMTP config lost |
| 000044 | `scanner_binary_versions`              | ✅ Yes         | Drops the scanner-binary-versions table and approval-event column |
| 000045 | `namespace_org_claims`                 | ✅ Yes         | Drops the namespace-ownership table; bindings are re-derived from artifacts on re-apply |
| 000046 | `user_token_revocations`               | ✅ Yes         | Drops the per-user token revocation table; outstanding revocations are lost, so any token revoked before the rollback becomes valid again until it expires |
| 000047 | `terraform_mirror_github_attestation`  | ✅ Yes         | Drops `verify_github_attestation` and `attestation_verified`; mirrors revert to unverified and the record of which artifacts were attested is lost |
| 000048 | `notification_channels`                | ✅ Yes         | Drops the notification-channel table (CASCADE); configured destinations must be re-added |
| 000049 | `add_org_owner_provisioner_roles`      | ✅ Yes         | Deletes the `org_owner` and `org_provisioner` system role templates; memberships referencing them are left with a NULL `role_template_id` by the FK's ON DELETE SET NULL, so those members lose their scopes |
| 000050 | `quarantine_orphaned_api_keys`         | ⚠️ No-op down  | Data-only: expires `api_keys` rows with `user_id IS NULL` (detached by a user deletion under `ON DELETE SET NULL`). The down cannot distinguish them from deliberately expired keys, so re-arming would undo the retirement; restore individual rows by hand. See `docs/upgrade-guide.md` |
| 000051 | `platform_admins`                      | ✅ Yes         | Drops the platform-admin carrier table. Safe today: every row is backfilled from an admin-bearing role template and effective admin is `carrier OR the existing scope union`, so the rollback changes nobody's authority. It stops being safe once grants are made through the management API (issue #766 PR 2) — those have no role-template equivalent and are lost; a `NULL` `note` identifies them |
| 000052 | `audit_outbox`                         | ⚠️ Conditional | Drops the audit outbox, its helper functions and the `platform_admins` constraint trigger that refuses any grant/revoke committing without an audit intent. **Rolling back reopens issue #766**: platform-admin authority can again change hands with no audit record. Any UNDELIVERED intents are destroyed with the table — drain them first (`SELECT count(*), min(occurred_at) FROM audit_outbox WHERE delivered_at IS NULL;` must read 0) since delivered ones are already in `audit_logs`. Requires PostgreSQL 13+ for `xid8`/`pg_current_xact_id()`; this product requires 14+ |
| 000053 | `admin_floor_report`                   | ⚠️ Partial     | Drops the `admin_floor_violations` view. The carrier rows the up migration backfills are deliberately NOT removed — deleting them would strip real authority from real people on a rollback (identify them with `note LIKE 'backfilled by migration 000053%'`). The migration never fails on pre-existing violations: it `RAISE WARNING`s and lets the deployment start, because a deployment with no administrator must still boot to be repairable. See `docs/administrator-floor.md` (issue #766) |
| 000054 | `platform_admin_carrier_only`           | ⚠️ Partial     | **BREAKING (issue #766).** Re-runs the platform-admin carrier backfill, then removes the `admin` scope from every role template (replacing it with the `org_owner` scope set so no organization is stranded), then REFUSES to apply — rolling everything back — if the deployment had a platform administrator and would have none afterwards. Platform-admin authority derives from `platform_admins` alone from this release; `admin` on a role template confers nothing. The down restores the seeded `admin` template's `["admin"]` scope and migration 000053's `admin_floor_violations` definition, and deliberately does NOT restore custom templates (they were not recorded) or delete backfilled carrier grants. **Roll the binary back first** — restoring the template under the new binary achieves nothing. If the migration refuses, the schema is left dirty: grant the carrier by hand (see `docs/administrator-floor.md`), then `migrate force 53` and re-run |
| 000055 | `registry_role_tables`                 | ✅ Yes         | Drops `organization_member_roles` and `registry_role_templates`, registry's own per-app authorization tables (sethbacon/terraform-suite-identity#206). Safe while nothing reads them: every row is derived, either dual-written beside the authoritative write to `organization_members` / `role_templates` or reconciled from those at startup, so the rollback changes no authorization decision. The up migration creates both tables EMPTY and deliberately performs no SQL backfill — the effective source depends on the identity pool's `search_path` and target database, neither of which is visible from SQL, so the backfill runs in Go at startup instead (`ReconcileMemberRoles`). Stops being safe once the read cutover ships; roll the binary back first |
| 000056 | `drop_identity_attribution_fks`         | ⚠️ No-op down | Drops the 24 foreign keys from registry feature tables to `users`/`organizations` (issue #883). The down is a deliberate no-op: re-adding validates the whole table and fails on exactly the deployments the up migration repaired, leaving the version dirty, while `NOT VALID` would silently restore the outage for new writes. Reasoning and by-hand restore SQL are in the `.down.sql` |

## How to Run Migrations

### Forward (upgrade)

Migrations run automatically on server startup. The backend uses
[golang-migrate](https://github.com/golang-migrate/migrate) to apply pending
migrations in order.

```bash
# Explicit migration (without starting the server)
migrate -path backend/internal/db/migrations \
  -database "postgres://user:pass@host:5432/terraform_registry?sslmode=disable" \
  up
```

### Rollback (downgrade)

```bash
# Roll back the last migration
migrate -path backend/internal/db/migrations \
  -database "postgres://user:pass@host:5432/terraform_registry?sslmode=disable" \
  down 1

# Roll back to a specific version
migrate -path backend/internal/db/migrations \
  -database "postgres://user:pass@host:5432/terraform_registry?sslmode=disable" \
  goto 23
```

### Check current version

```bash
migrate -path backend/internal/db/migrations \
  -database "postgres://user:pass@host:5432/terraform_registry?sslmode=disable" \
  version
```

### Fix dirty state

If a migration fails partway through, the schema_migrations table may be marked
dirty. Fix manually:

```bash
# Force the version to the last known-good migration
migrate -path backend/internal/db/migrations \
  -database "postgres://user:pass@host:5432/terraform_registry?sslmode=disable" \
  force 23

# Or use the fix-migration helper, which clears the dirty flag automatically
# (pass --dry-run to only report the current migration state)
go run ./cmd/fix-migration
```

## Rollback Procedures by Version Upgrade

### Rolling back 1.0.0 → 0.10.x

The 1.0.0 line adds migrations 027–040 on top of the 0.10.0 schema (which ended at
migration 026). To return to 0.10.x, roll back to migration 026:

```bash
# 1. Stop the 1.0.0 backend
# 2. Roll back migrations 027–040 (one version at a time)
migrate ... goto 26
# 3. Deploy 0.10.x
# 4. Verify: curl /health
```

**Data loss:** LDAP setup config, CVE advisories, UI theme config, scan execution
logs, signature storage keys, and all version-approval state (including the
`version_approval_events` table) are dropped. Migration 039's down also fails if any
`terraform_mirror_configs` rows use the `packer`/`sentinel`/`opa` tools — update or
remove those rows before rolling back past 039.

### Rolling back 0.10.0 → 0.9.x

```bash
# 1. Stop the 0.10.0 backend
# 2. Roll back migration 026 (org_quotas)
migrate ... down 1
# 3. Deploy 0.9.x
# 4. Verify: curl /health
```

**Data loss:** Quota configurations and usage tracking will be lost.

### Rolling back 0.9.0 → 0.8.x

```bash
# 1. Stop the 0.9.0 backend
# 2. Roll back migrations 025 (org_idp_binding)
migrate ... goto 24
# 3. Deploy 0.8.x
# 4. Verify: curl /health
```

**Data loss:** Per-org IdP bindings will be lost. SAML/LDAP users will need reconfiguration.

### Rolling back 0.8.0 → 0.7.x

```bash
# 1. Stop the 0.8.0 backend
# 2. Roll back migrations 024-025
migrate ... goto 23
# 3. Deploy 0.7.x
# 4. Verify: curl /health
```

**Data loss:** Module deprecation metadata and org IdP bindings.

## Best Practices

1. **Always back up before upgrading** — `pg_dump -Fc terraform_registry > pre-upgrade.dump`
2. **Test rollback in staging** before relying on it in production
3. **Never skip versions** in rollback — go one version at a time
4. **Check for dirty state** after any failed migration before retrying
5. **Review .down.sql files** before executing a rollback to understand data impact
