<!-- markdownlint-disable MD013 -->
# 11. Version Approval Gate for Mirrors

**Status**: Accepted

## Context

Provider and Terraform binary mirrors sync versions from upstream as soon as
they are published. Static version filters (`latest:N`, semver constraints,
`stable_only`) decide *which* versions to mirror, but they cannot express
"hold this version until a human has reviewed it." Regulated and
security-conscious organizations need to vet a mirrored version before
developers can consume it, and they need an audit record of who approved what.

We needed a gate that:

1. Is opt-in per mirror and zero-cost when unused.
2. Hides un-reviewed versions from every client-facing protocol endpoint.
3. Never retroactively hides versions that were already visible.
4. Supports automatic approval of low-risk versions to keep review volume sane.
5. Records an audit trail of every decision.

## Decision

Add an `approval_status` column to `mirrored_provider_versions` and
`terraform_versions` with four states: `NULL` (not gated), `pending_approval`,
`approved`, `rejected`. Mirror configs gain a `requires_approval` flag and an
optional `auto_approve_rules` JSONB column.

### Filtering at the listing endpoints

The protocol endpoints that enumerate versions exclude
`pending_approval`/`rejected` rows:

- Provider Registry Protocol version listing (`provider_versions` filtered by a
  `NOT EXISTS` against the gated `mirrored_provider_versions` row).
- Network Mirror Protocol `index.json` (`ListVisibleVersions`).
- Terraform binary mirror version/latest/download endpoints (in-handler filter
  on `approval_status`).

`NULL` is the common case and is indexed with a partial index, so ungated
mirrors pay no measurable cost.

### Auto-approve rules

A small pure evaluator (`internal/mirror/auto_approve.go`) runs at sync time
against each new version: `patch_only`, `gpg_verified`, `semver_constraint`,
and `delay_hours`, combined with mode `any` (first match wins) or `all`.
Matches are recorded as `approved` with an `auto_approved` audit event naming
the rule; unknown rule types fail closed.

### Audit trail

`version_approval_events` records every auto or manual decision (action, acting
user, notes, matched rule). A single uniform admin API
(`/api/v1/admin/version-approvals`) presents both provider and terraform gated
versions through one DTO and supports single + bulk approve/reject plus the
per-version event trail.

### "Latest" recomputation

Because Terraform binary mirrors store an `is_latest` flag, approving or
rejecting a terraform version recomputes `is_latest` over the visible
(NULL/approved), synced, non-deprecated set. Provider "latest" is derived
dynamically from the filtered listing, so no stored flag changes are needed.

## Consequences

**Easier**:

- Operators can vet upstream releases before exposing them, with a full audit
  trail.
- Auto-approve rules keep routine versions (patch bumps, signed releases)
  flowing without manual work.
- Opt-in design means existing deployments are unaffected until they enable it.

**Harder**:

- `approval_status` lives on the mirror-tracking tables, so the Provider
  Registry Protocol listing must join through `mirrored_provider_versions` to
  filter — a `NOT EXISTS` subquery rather than a column on `provider_versions`.
- For terraform binary mirrors GPG verification is per-platform and happens
  after version discovery, so the `gpg_verified` auto-approve rule does not fire
  at discovery time for binaries (documented; use other rules or manual review).
- A re-sync must never reset an already-decided version, so the upsert paths
  deliberately leave `approval_status` untouched on conflict.
