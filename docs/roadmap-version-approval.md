# Roadmap: Version Approval for Mirrors

## Summary

Add a version-level approval gate to provider mirrors and terraform binary mirrors. When enabled, newly synced versions enter `pending_approval` state and are hidden from Terraform clients until an administrator approves them. This makes "latest" = "latest approved version."

## Motivation

Organizations need to vet mirrored provider versions before exposing them to developers. Static version filters (`latest:N`, semver constraints) cannot express "approve after review." A dynamic approval gate lets teams ensure only validated versions reach production infrastructure code.

## Design

- `approval_status` column on `mirrored_provider_versions` and `terraform_versions`
- States: `NULL` (not gated), `pending_approval` (hidden), `approved` (visible), `rejected` (permanently hidden)
- Protocol endpoints filter: `WHERE approval_status IS NULL OR approval_status = 'approved'`
- Auto-approve rules evaluated at sync time (patch-only, GPG-verified, semver constraint, delay-hours)
- Post-approval removal via existing deprecation mechanism

## Schema Changes

Migration `000037_version_approval.up.sql`:

```sql
ALTER TABLE mirrored_provider_versions
  ADD COLUMN approval_status VARCHAR(20) DEFAULT NULL
    CHECK (approval_status IN ('pending_approval', 'approved', 'rejected'));

ALTER TABLE terraform_versions
  ADD COLUMN approval_status VARCHAR(20) DEFAULT NULL
    CHECK (approval_status IN ('pending_approval', 'approved', 'rejected'));

ALTER TABLE mirror_configurations
  ADD COLUMN auto_approve_rules JSONB DEFAULT NULL;
ALTER TABLE terraform_mirror_configs
  ADD COLUMN auto_approve_rules JSONB DEFAULT NULL;

CREATE TABLE version_approval_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mirrored_provider_version_id UUID REFERENCES mirrored_provider_versions(id) ON DELETE CASCADE,
    terraform_version_id UUID REFERENCES terraform_versions(id) ON DELETE CASCADE,
    action VARCHAR(20) NOT NULL CHECK (action IN ('auto_approved', 'approved', 'rejected')),
    performed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    notes TEXT,
    auto_approve_rule VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT exactly_one_target CHECK (
      (mirrored_provider_version_id IS NOT NULL)::int +
      (terraform_version_id IS NOT NULL)::int = 1
    )
);
```

## API Endpoints

| Method | Path                                            | Purpose                    | Scope        |
| ------ | ----------------------------------------------- | -------------------------- | ------------ |
| GET    | `/api/v1/admin/version-approvals`               | List by status/type/config | mirrors:read |
| GET    | `/api/v1/admin/version-approvals/pending-count` | Dashboard badge count      | mirrors:read |
| PUT    | `/api/v1/admin/version-approvals/:id/approve`   | Approve single version     | admin        |
| PUT    | `/api/v1/admin/version-approvals/:id/reject`    | Reject single version      | admin        |
| POST   | `/api/v1/admin/version-approvals/bulk-approve`  | Bulk approve               | admin        |
| POST   | `/api/v1/admin/version-approvals/bulk-reject`   | Bulk reject                | admin        |
| GET    | `/api/v1/admin/version-approvals/:id/events`    | Audit trail                | mirrors:read |

## Auto-Approve Rules

```json
{
  "rules": [
    {"type": "patch_only"},
    {"type": "gpg_verified"},
    {"type": "semver_constraint", "constraint": ">=5.0, <6.0"},
    {"type": "delay_hours", "hours": 24}
  ],
  "mode": "any"
}
```

| Rule                | Behavior                                                        |
| ------------------- | --------------------------------------------------------------- |
| `patch_only`        | Approve if only patch incremented from highest existing version |
| `gpg_verified`      | Approve if GPG signature verified during sync                   |
| `semver_constraint` | Approve if version matches the constraint                       |
| `delay_hours`       | Auto-approve after N hours via background sweep                 |

Mode: `"any"` (first match wins) or `"all"` (all must match).

## Files to Change

| File                                                      | Change                                          |
| --------------------------------------------------------- | ----------------------------------------------- |
| `internal/db/migrations/000037_version_approval.up.sql`   | New migration                                   |
| `internal/db/models/mirror.go`                            | Add `AutoApproveRules`, `ApprovalStatus` fields |
| `internal/db/models/terraform_mirror.go`                  | Add `AutoApproveRules`, `ApprovalStatus` fields |
| `internal/db/models/version_approval.go`                  | New: event + rules structs                      |
| `internal/db/repositories/version_approval_repository.go` | New: CRUD + bulk ops                            |
| `internal/mirror/auto_approve.go`                         | New: rule evaluation logic                      |
| `internal/jobs/mirror_sync.go`                            | Set pending status, evaluate auto-approve       |
| `internal/jobs/terraform_mirror_sync.go`                  | Same + skip `is_latest` for pending             |
| `internal/api/admin/version_approvals.go`                 | New: admin handlers                             |
| `internal/api/router.go`                                  | Register new route group                        |
| `internal/api/providers/versions.go`                      | Filter pending from response                    |
| `internal/api/mirror/index.go`                            | Filter pending from index.json                  |
| `internal/api/terraform_binaries/binaries.go`             | Filter pending from list/latest                 |
| `internal/services/pull_through.go`                       | Set pending on pull-through versions            |

## Tests

| File                                                           | Coverage                                     |
| -------------------------------------------------------------- | -------------------------------------------- |
| `internal/mirror/auto_approve_test.go`                         | All rule types, modes, edge cases (15 tests) |
| `internal/db/repositories/version_approval_repository_test.go` | CRUD, bulk, is_latest recalc (18 tests)      |
| `internal/api/admin/version_approvals_test.go`                 | All endpoints, validation, errors (20 tests) |
| `internal/api/mirror/index_test.go`                            | Pending hidden, no-approval passthrough      |
| `internal/api/terraform_binaries/binaries_test.go`             | Pending hidden, latest skips pending         |
| `internal/jobs/mirror_sync_test.go`                            | Pending set, auto-approve during sync        |
| `internal/jobs/terraform_mirror_sync_test.go`                  | Pending set, is_latest not set               |

## Documentation

- `docs/version-approval.md` — user-facing feature guide
- `docs/adr/NNN-version-approval.md` — architecture decision record
- `docs/api-reference.md` — endpoint table addition
- `docs/configuration.md` — mirror config field docs
- `docs/architecture.md` — sync flow update
- Swagger annotations on all new handlers → regenerate `swagger.yaml`

## Implementation Order

1. Migration + models
2. Auto-approve evaluator + tests
3. Repository layer + tests
4. Sync job integration + tests
5. Protocol endpoint filtering + tests
6. Admin API endpoints + tests
7. Documentation (feature guide, ADR, swagger, config, architecture)

## Backward Compatibility

- `approval_status = NULL` means "not subject to approval" — all existing versions remain visible
- Enabling `requires_approval` only gates future syncs, not existing versions
- Mirrors without the flag behave exactly as before (zero performance cost)
