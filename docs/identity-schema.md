# Shared Identity Schema

The registry can serve its identity tables — `users`, `organizations`,
`organization_members`, `api_keys`, `role_templates`, `oidc_config`, `audit_logs`,
`revoked_tokens` — from a dedicated, **shared** PostgreSQL `identity` schema instead of
the application's own `public` schema. This lets the registry and the other apps in the
Terraform tooling suite (e.g. the state manager) share **one** identity store, so a user,
organization, or API key is the same across the suite.

The identity layer lives in the [`terraform-suite-identity`](https://github.com/sethbacon/terraform-suite-identity)
Go module ([ADR 012](adr/012-shared-identity-component.md)). That module is a **library**
linked into the registry binary — not a separate service. There is nothing extra to deploy.

---

## This is optional and off by default

> **You do not need any of this to run the registry.** By default the registry is fully
> self-contained: its identity tables live in its own `public` schema, created by its own
> migrations, with no separate schema, no shared database, and no other app involved. The
> shared identity schema is **opt-in** — it exists for operators who deliberately want the
> registry and the state manager to share one identity store.

Two environment flags gate the feature, **both default `false`**:

| Variable                          | Default    | Effect                                                                                                                                                    |
| --------------------------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TFR_IDENTITY_MIGRATIONS_ENABLED` | `false`    | Run the shared identity migrations at startup (create/update the `identity` schema). Additive and safe; does **not** change runtime behaviour on its own. |
| `TFR_IDENTITY_SCHEMA_ENABLED`     | `false`    | Route identity reads/writes at the `identity` schema (`search_path=identity,public`). Requires the schema to exist.                                       |
| `TFR_IDENTITY_SCHEMA_NAME`        | `identity` | The schema name.                                                                                                                                          |

Leaving both unset keeps the registry on `public` — the supported standalone path.

---

## How routing works

When `TFR_IDENTITY_SCHEMA_ENABLED=true`, the registry opens a dedicated connection pool
whose `search_path` is `identity,public`. Identity repositories use that pool, so
unqualified identity table names resolve at the `identity` schema; the app's own feature
tables (modules, providers, mirrors, …) keep using the primary `public` pool. The flag is
reversible — turning it off routes identity access back to `public`.

---

## Cross-schema foreign keys (removed in migration 000056)

> **If you are upgrading from a release before migration `000056`, read this.**

The registry's **feature** tables (`modules`, `providers`, `namespace_claims`,
`mirror_*`, `scm_*`, `storage_*`, …) store the id of the user or organization that
created a row. Those columns used to carry foreign keys into the identity tables, and
migrations `000038` and `000045` chose the target schema at migration time by asking
whether the `identity` schema existed.

**That was wrong, and migration `000056` drops all 24 of those constraints** (issue #883).
Schema existence is not schema authority. `TFR_IDENTITY_MIGRATIONS_ENABLED` creates the
schema; `TFR_IDENTITY_SCHEMA_ENABLED` decides whether the application reads and writes it.
Step 1 of the rollout below deliberately sits between the two — and any deployment that
enables migrations without the cutover sits there permanently. In that state the
constraints resolved at `identity` while every row the application wrote carried a
`public` id, so:

- `POST /api/v1/modules` failed with `500 {"error":"Failed to claim namespace"}`
  (`namespace_claims_organization_id_fkey`), and the module row itself was rejected too;
- the **network mirror's pull-through cache** could not populate a provider on an
  anonymous `GET .../index.json`, because that path inserts into `providers` in the
  request (`providers_organization_id_fkey`).

Repointing them at `public` instead would only move the breakage to the deployments that
did cut over, and where identity lives in a separate database (`TFR_IDENTITY_DATABASE_*`)
PostgreSQL cannot express the constraint at all. So the registry now stores these ids as
plain attributions, with no database constraint, in every topology — the same choice
migrations `000046_user_token_revocations` and `000051_platform_admins` already made.

**Nothing to do on upgrade.** `000056` is idempotent, drops by constraint name (so it
works whichever schema they currently resolve at, including a hand-edited custom schema
name), scans no data, and is fast on any table size. Identity's *own* tables — `api_keys`,
`audit_logs`, `oidc_config`, `org_quotas`, `org_quota_usage`, `organization_members`,
`revoked_tokens` — keep their foreign keys; they move to the `identity` schema wholesale
at cutover and their constraints travel with them.

### What enforces these invariants now

- **Organization deletion** is refused with `409` while the organization owns namespace
  claims or module/provider rows (`OrganizationHandlers.DeleteOrganizationHandler`). This
  is now the only enforcement, not a friendlier face on a database constraint.
- **User deletion** destroys the principal's API keys, JWT watermark and **SCM OAuth
  tokens** in application code before the user row is removed.
- Attribution columns (`created_by`, `published_by`, `claimed_by`, …) are no longer
  scrubbed or blocked when a user is deleted; a deleted user's UUID can remain in one.
  Every consumer `LEFT JOIN`s, so the effect is a blank author, and the
  separate-identity-database topology has always behaved this way.

### Caveat: non-default schema name

`TFR_IDENTITY_SCHEMA_NAME` still only affects the runtime `search_path`. The identity
library creates the schema under the literal name `identity`, and several registry
migrations reference that literal. Setting it to anything else is not supported without
hand-editing migrations, and there is no startup validation that catches the mismatch.

---

## Rollout

### New deployment

1. Set `TFR_IDENTITY_MIGRATIONS_ENABLED=true` and `TFR_IDENTITY_SCHEMA_ENABLED=true`.
2. Start the registry. It runs the identity migrations (creating the `identity` schema,
   seeding the default organization and role templates) and routes identity access there.
3. Layer your role → scope mapping onto `identity.role_templates` (the registry seeds
   identity-core scopes; each app extends them at setup).

### Existing deployment (data already in `public`)

1. **Enable migrations only.** Set `TFR_IDENTITY_MIGRATIONS_ENABLED=true`, leave
   `TFR_IDENTITY_SCHEMA_ENABLED` unset, and deploy. The `identity` schema is created
   alongside `public`; runtime behaviour is unchanged. Verify:

   ```sql
   SELECT version, dirty FROM identity.identity_schema_migrations;
   ```

2. **Copy identity data `public` → `identity`,** preserving UUIDs, in dependency order
   (organizations and role_templates first, then users, then the rest). Use
   `INSERT … SELECT … ON CONFLICT DO NOTHING` so the seeded default org / role templates
   are not duplicated. Keeping the same UUIDs is what allows existing users to keep
   publishing after the cutover (see the limitation above).

3. **Enable the cutover.** Set `TFR_IDENTITY_SCHEMA_ENABLED=true` and deploy. Identity
   reads/writes now resolve at `identity`.

4. **Verify** (see below).

### Verification

After enabling the cutover, log in via OIDC and create an API key, then confirm the writes
landed in the `identity` schema:

```sql
SELECT oidc_sub IS NOT NULL AS linked FROM identity.users WHERE email = '<you>';
SELECT count(*) FROM identity.api_keys;   -- your new key
SELECT count(*) FROM identity.audit_logs; -- the login/key audit rows
```

### Rollback

Set `TFR_IDENTITY_SCHEMA_ENABLED=false` and deploy. Identity access routes back to
`public`. Any rows written **only** to `identity` since the cutover would need copying back
to `public` to remain visible.

---

## Registry's own authorization tables (per-app authorization)

Migration `000055` adds two tables that belong to **registry**, not to identity:

| Table | Holds |
| --- | --- |
| `registry_role_templates` | registry's own role → scope definitions |
| `organization_member_roles` | `(organization_id, user_id) → role_template_id` — the role a member holds **in registry** |

They exist because identity is shared across the suite while authorization is
per-application (design: `sethbacon/terraform-suite-identity#206`). Eventually
`organization_members` carries membership only, and the role moves here.

**These tables are now what registry reads.** Every role and every scope set behind
every authorization decision comes from `organization_member_roles` joined to
`registry_role_templates`. The identity tables are still **written** — every role
assignment lands in `organization_members.role_template_id` first and is mirrored here
only on success — and that is deliberate: it is what makes the rollback below real, and
what the state manager still reads.

What has **not** moved is the membership *fact*. "Is this principal a member of this
organization at all" is still answered by `organization_members`, and every accessor asks
that first. A stale row in `organization_member_roles` for somebody who is not a member
therefore confers nothing today; it becomes reachable only in phase 4, which is why the
drift check reports it now.

`registry_role_templates` carries a prefix only because `public.role_templates` still
exists; it takes the unprefixed name when that duplicate is dropped. Neither table has a
foreign key into identity — identity may be another schema or another database, where
such a key cannot be expressed at all (same reasoning as `000046` and `000051`).

### `role-drift` — the gate, and the standing check

```console
$ role-drift            # exits 0 only if the two copies agree
$ role-drift -v         # also prints what was compared
```

| Exit | Meaning |
| --- | --- |
| `0` | the two copies agree |
| `1` | they disagree; every disagreement is printed |
| `2` | the comparison could not be made — unreachable table, bad config |

`2` is not `1`. "Could not check" must never be spelled the same way as "checked and
found nothing", or a misconfigured run gates a cutover open.

It reads the same config file and the same `TFR_IDENTITY_*` environment as the server, so
it compares what the server compares rather than deciding the topology for itself. It
also works when identity is a **separate database**, which the single-statement SQL
version this replaces could not: no statement can join two databases.

What it reports:

| Kind | Meaning |
| --- | --- |
| `mirror_without_membership` | registry holds a role for a non-member. Inert today; **grants** authority the product never issued once phase 4 lands. |
| `role_differs` | both copies have the membership and name different templates. |
| `membership_not_mirrored` | identity has the membership, registry has no row — the principal is served **no role**. |
| `template_scopes_differ` | same template id, different scope sets: every holder's authority differs. |
| `template_name_differs` | same id, different name. Registry resolves templates by name in the group-mapping reconciliation and the admin API. |
| `template_not_mirrored` / `mirrored_template_orphaned` | a template exists on one side only. |
| `membership_role_missing_template` | an identity membership names a template that does not exist **in identity**. The source data is wrong; the reconcile mirrors it with no role rather than inventing one. |
| `unparseable_row` | a source row whose `organization_id` or `user_id` is not a UUID. It can never be mirrored, so it is permanently unreconciled. |

The last four are cases the pre-3b SQL query could not see at all.

### What an operator does about a non-empty result

Rows here now **do** affect authorization — that is what changed. In order of cost:

1. **Restart the backend.** The startup reconcile re-derives both tables from the identity
   tables and is the intended repair for anything a transient mirror-write failure left
   behind. Re-run `role-drift`; most results clear here.
2. **If rows persist, read the boot log.** `registry role tables reconciled` reports what
   the last pass did, including `orphaned_role_refs` and `unparseable_rows`. A membership
   whose role template is missing is an inconsistency in the *identity* data; decide what
   that member's role should be and set it through the normal member API, which repairs
   both sides.
3. **A `mirror_without_membership` row is worth understanding before deleting.** It means a
   membership was removed without its mirror row, or a role was written for somebody who
   was never a member.

### Divergence is also reported at request time

`role-drift` runs when somebody runs it. Between runs, the read path reports disagreement
on the request that is actually being served the wrong role, because every accessor still
has both answers in hand — the identity columns it queried and registry's:

- metric `registry_role_read_divergence_total{accessor,kind}`, where `kind` is
  `missing_mirror` or `role_differs`. **Steady state is zero.** Alert on
  `increase(...) > 0`, not on a threshold.
- an `ERROR` log naming the organization, the user, and both role template ids.

What it does **not** catch, stated as limits rather than claims:

- a principal nobody authenticates as. It fires on reads; a dormant account is invisible
  until `role-drift` runs.
- `mirror_without_membership`. Every accessor asks the store for the membership first, so
  a mirrored row for a non-member is never reached — which is also why it confers nothing.
  Only `role-drift` sees it.
- two templates that agree by id and differ in scopes. The per-request comparison is on the
  role template **id**, because that is what both sides carry per membership; scope
  equality is a property of the template tables and is `role-drift`'s second half.

### Rollback

**Deploy the previous image.** That is the whole mechanism, and there is nothing
finer-grained — no flag, no environment variable, no per-request switch.

It works because the previous image reads `organization_members.role_template_id` joined
to `role_templates`, and this release never stopped writing them: every role assignment
still lands there first, the shared role templates are still seeded, and nothing has been
dropped. A deployment that rolls back therefore returns to a copy that has been kept
current the whole time, with no data step.

Rolling **forward** again needs no step either: the startup reconcile re-derives
registry's tables from the identity tables on every boot.

### A separate identity database now refuses to boot

When identity lives in its own database, the connection registry resolves identity reads
through cannot see registry's own tables. Before this release that was logged and
survivable, because nothing read them. It is not survivable now — every principal would
resolve to no role — so the backend refuses to start:

```text
FATAL registry's own role tables (migration 000055) are not reachable from the connection
      this process resolves identity reads through ...
```

Create `registry_role_templates` and `organization_member_roles` where that connection can
resolve them, or run identity in the registry database. This is the same topology in which
migration `000051`'s backfill and `000054`'s assertions are already inoperative, and in
which registry issue #883 applies.

---

## See also

- `docs/configuration.md` — the full environment-variable reference.
- [ADR 012](adr/012-shared-identity-component.md) (shared identity component) in the registry and state-manager repositories.
