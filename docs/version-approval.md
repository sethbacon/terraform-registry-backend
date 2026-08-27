# Version Approval for Mirrors

Version approval is an optional gate that holds newly mirrored provider and
Terraform/OpenTofu binary versions for administrator review before they become
visible to Terraform clients. When enabled, **"latest" means "latest approved
version"** — unreviewed versions are hidden from the protocol endpoints.

## When to use it

Organizations that vet upstream releases before exposing them to developers
need more than the static version filters (`latest:N`, semver constraints).
Those filters cannot express "approve after review." The approval gate adds a
dynamic, per-version decision so only validated versions reach production
infrastructure code.

## How it works

1. Enable **Require approval** on a provider mirror or Terraform binary mirror
   configuration.
2. On the next sync, each newly discovered version is recorded with
   `approval_status = pending_approval` and is **hidden** from:
   - the Provider Registry Protocol version listing,
   - the Network Mirror Protocol `index.json`,
   - the Terraform binary mirror version/latest/download endpoints.

   Hidden versions are also rejected by the provider and Terraform binary
   **download** endpoints (a direct request for a pending/rejected version
   returns 404), so the gate cannot be bypassed by referencing a version
   directly.
3. An administrator reviews pending versions on the **Version Approvals** admin
   page and approves or rejects each one (individually or in bulk).
4. Approved versions become visible; rejected versions stay permanently hidden.

`approval_status` has four states:

| State              | Meaning                                       | Visible to clients |
| ------------------ | --------------------------------------------- | ------------------ |
| `NULL`             | Not subject to approval (mirror not gated)    | Yes                |
| `pending_approval` | Awaiting review                               | No                 |
| `approved`         | Reviewed and accepted                         | Yes                |
| `rejected`         | Reviewed and rejected (permanent)             | No                 |

### What the gate does not cover

The gate vets content that arrives from **outside** this registry. It does not
apply to:

| Not gated | Why |
| --- | --- |
| Modules | No approval concept exists for modules anywhere in the schema. A module published here came from a principal that already held publish rights under a claimed namespace. |
| Locally uploaded provider versions | Only the mirrored tracking row carries a verdict; a version with no mirrored row is treated as visible. |

**Modules are deliberately ungated** (decided 2026-08-27, #975). A module
published here came from a principal that already held publish rights under a
claimed namespace, enforced on every mutation by `NamespaceAuthorizer` — so this
gate's question, *should this upstream artifact be trusted*, does not arise for
it.

Do not describe this gate as the control over what may be consumed. It is the
control over what may be **mirrored in**.

### One verdict per artifact, shared by every organization

`approval_status` lives on a single row per artifact, and every enforcement
point reads that one row. The admin **queue** is correctly scoped per
organization — it sources the organization from the mirror configuration and
fails closed on an empty scope — but the **decision** is not.

So two organizations mirroring the same upstream provider through separate
mirror configurations cannot hold different verdicts on it. **The first to
approve decides for everyone; the first to reject does too.** A second
organization's administrator sees the artifact leave their queue without having
acted on it.

This is a known and accepted limitation, not a subtlety of the design. Under the
[estate tenancy model](https://github.com/sethbacon/terraform-suite-identity/blob/main/docs/tenancy-model.md),
version approval and mirror configuration gate which providers a **host**
offers, so the fix is a re-key of the verdict to per-(host, artifact) — which is
part of the host work rather than a change that can be made independently of it.
Re-keying it per-organization first was considered and rejected (2026-08-27):
the host work would re-key the same column again, and running two migrations
over one authorization verdict is how one of them ends up half-applied.

Until then: if two organizations need independent verdicts on the same upstream
provider, they need separate deployments.

### Backward compatibility

- Existing versions keep `approval_status = NULL` and remain visible.
- Enabling **Require approval** only gates **future** syncs, never existing
  versions.
- Mirrors without the flag behave exactly as before, with zero filtering cost.

## Enabling the gate

The **Require approval** toggle maps to the `requires_approval` boolean on the
mirror configuration (both provider mirrors and Terraform binary mirrors). The
optional auto-approve rules described below live in the `auto_approve_rules`
JSONB field on the same configuration. Both fields are set through the admin
mirror API/UI rather than static config; see
[configuration.md](configuration.md) for the mirror-configuration fields and the
[API reference](api-reference.md) for the admin mirror endpoints.

## Auto-approve rules

To avoid manual review of low-risk versions, a gated mirror can carry an
optional set of auto-approve rules (stored as JSON in the mirror config's
`auto_approve_rules` field). Rules are evaluated at sync time; a version that
matches is recorded as `approved` instead of `pending_approval`, and an
`auto_approved` audit event records which rule fired.

```json
{
  "rules": [
    { "type": "patch_only" },
    { "type": "gpg_verified" },
    { "type": "semver_constraint", "constraint": ">=5.0, <6.0" },
    { "type": "delay_hours", "hours": 24 }
  ],
  "mode": "any"
}
```

| Rule                | Behaviour                                                        |
| ------------------- | --------------------------------------------------------------- |
| `patch_only`        | Approve if only the patch increments from the highest existing version on the same major.minor line |
| `gpg_verified`      | Approve if the GPG signature was verified during sync           |
| `semver_constraint` | Approve if the version satisfies the constraint                 |
| `delay_hours`       | Approve once the version has been pending for at least N hours (applied on subsequent syncs) |

- **Mode `any`** (default): the first matching rule approves the version.
- **Mode `all`**: every rule must match.
- Unknown rule types never match (fail closed).

> **Note:** For Terraform binary mirrors, GPG verification happens per-platform
> after download, so the `gpg_verified` rule does not fire at version-discovery
> time. Use `patch_only`, `semver_constraint`, or `delay_hours` for binary
> mirrors, or review those versions manually.

## Administration

The **Version Approvals** page (admin scope `mirrors:read` to view, `admin` to
act) lists gated versions filtered by status and type, shows GPG verification
state and sync time, and exposes the per-version audit trail. See the
[API reference](api-reference.md) for the underlying endpoints.

## Audit trail

Every decision — auto or manual — is recorded in `version_approval_events` with
the action, the acting user (for manual decisions), optional notes, and the
matched rule name (for auto-approvals). The trail is shown inline on the
approvals page and returned by
`GET /api/v1/admin/version-approvals/{id}/events`.
