# The administrator floor

Two invariants the registry now enforces on every write path (issue #766):

- **A — the deployment always has at least one platform administrator.**
- **B — every organization with members always has at least one member who can
  administer it.**

Both are enforced by `backend/internal/adminfloor`, which serialises the
check-then-write on a deployment-wide Postgres advisory lock and refuses any
change that would break either one.

---

## What counts as an administrator

**Platform administrator** — a principal holding either

- a row in `platform_admins` (the carrier, migration `000051`), or
- an organization membership whose role template carries the `admin` scope
  (the org-less scope union, #652).

Effective platform-admin authority is `carrier OR union`, so the floor counts
the union of both. Refusing a change because the carrier happens to be empty,
while four role-template administrators remain, would be a refusal with no
hazard behind it.

**Organization administrator** — a member whose role template carries `admin`
or `organizations:write`. That is not a new definition: `organizations:write`
is exactly what `RequireOrgScopeForPathOrg` demands on every membership route,
so an organization with no holder of it cannot add, remove or re-role anybody.

**Exercisable, not merely recorded.** A grant that resolves to no user is
skipped rather than counted. Both auth middlewares load the user before
consulting the carrier, so an orphan row elevates nobody; counting it would let
the last real administrator be removed against a count of two.

---

## An organization with no members is legitimate

Stated explicitly because it is the question invariant B turns on.

- `members == 0` — **allowed.** The empty set. The invariant is vacuous over it.
- `members >= 1 && administrators == 0` — **refused.** The organization exists,
  people are in it, and none of them can manage it.

So you may remove the last *member* of a wound-down organization; you may not
remove or demote the last *administrator* while other members remain. The
stricter reading ("an organization must always have an administrator, full
stop") would make deleting the organization the only way to offboard its final
person, which is a refusal with no hazard behind it.

An organization can also be *created* with zero members: a request whose
principal is an organization-bound API key with a `NULL` `user_id` — an
organization service credential — has no creator to enrol. That is logged at
`WARN` and the organization is created; any platform administrator can add its
first member.

---

## Where it is enforced

| Path | Route / entry point |
| --- | --- |
| Explicit platform-admin revoke | `DELETE /api/v1/admin/platform-admins/{user_id}` |
| Member removal | `DELETE /api/v1/organizations/{id}/members/{user_id}` |
| Member role change, including `role_template_id: null` | `PUT /api/v1/organizations/{id}/members/{user_id}` |
| Organization deletion (memberships go by FK cascade) | `DELETE /api/v1/organizations/{id}` |
| User deletion | `DELETE /api/v1/users/{id}` |
| GDPR erasure | `POST /api/v1/admin/users/{id}/erase` |
| SCIM deprovision ×4 | `DELETE /scim/v2/Users/{id}`, `PUT` with `active:false`, both PATCH forms |
| IdP group-mapping removal and downgrade | on login, `reconcileGroupMemberships` |

`backend/internal/api/admin/admin_floor_class_test.go` walks the whole module
and fails if a new authority-reducing write appears without the guard, or
without a reasoned entry in its exemption map.

### Responses

| Outcome | HTTP | Body |
| --- | --- | --- |
| Would leave no platform administrator | `409` | `This would leave the deployment with no platform administrator` |
| Would leave an organization with no administrator | `409` | `This would leave the organization with no administrator` |
| The floor could not be established | `500` | `Failed to verify that an administrator would remain` |

SCIM returns `409` with an equivalent `detail`. A `500` is **not** a refusal —
nothing was decided, and the change did not happen.

### The IdP path is the deliberate exception

`reconcileGroupMemberships` runs *inside the login* the reduction is about. A
refusal there **skips the reduction and lets the login proceed**, logged at
`ERROR`. Failing the login instead would lock out exactly the person who has to
log in to fix the IdP mapping that caused it. The membership survives, which is
observable — but the registry and the IdP now disagree, so treat these log
lines as actionable:

```txt
<provider> group mapping deprovision SKIPPED: it would leave the deployment with no platform administrator
<provider> group mapping role reassignment SKIPPED: it would leave the organization with no administrator
```

---

## Bootstrap

The setup wizard (`POST /api/v1/setup/admin`) now writes **both** carriers: the
`admin` role-template membership it always wrote, and a `platform_admins` row.
Neither requires a pre-existing administrator.

If the carrier grant fails — the registry connection is down while the identity
connection is up — setup still succeeds (the membership already confers the
authority) and the response carries:

```json
{ "platform_admin_carrier_incomplete": true }
```

Repair it with `POST /api/v1/admin/platform-admins` once the connection is back.

Organization creation enrols the creator as `org_owner`, which is what
establishes invariant B for a new organization.

---

## Existing data may already violate these

Nothing prevented either violation before this release, so a deployment can
already be in a state the application will no longer let you reach. Migration
`000053` ships the detection query and **never fails a startup** on it: it
`RAISE WARNING`s and lets the deployment boot, because a deployment with no
administrator has to boot to be repairable.

### Detection

```sql
SELECT * FROM admin_floor_violations;
```

Empty means both invariants hold. Rows look like:

```txt
    scope     | organization_id | organization_name |                  violation
--------------+-----------------+-------------------+--------------------------------------------
 deployment   |                 |                   | the deployment has no exercisable platform administrator
 organization | 9f3c…           | acme              | organization has members but nobody who can administer it
```

A deployment with **no users at all** is deliberately not reported: that is a
migrated-but-not-yet-set-up database, and every fresh install passes through it.

> **The view reads the `public` schema.** Under `TFR_IDENTITY_SCHEMA_ENABLED`
> the live membership data is in `identity.*` and `public` holds only a
> pre-cutover copy; under `TFR_IDENTITY_DATABASE_*` it is in another database
> this view cannot see at all. In both cases the view will report "no
> violations" whatever the truth is. Run the equivalent below on the identity
> connection.

<details>
<summary>Identity-schema equivalent (<code>scopes</code> is <code>TEXT[]</code>, not <code>jsonb</code>)</summary>

```sql
-- Invariant A
SELECT 'deployment' AS scope
 WHERE EXISTS (SELECT 1 FROM identity.users)
   AND NOT EXISTS (
         SELECT 1 FROM identity.organization_members om
           JOIN identity.users u ON u.id = om.user_id
           JOIN identity.role_templates rt ON rt.id = om.role_template_id
          WHERE 'admin' = ANY(rt.scopes));
-- (the platform_admins half stays on the REGISTRY connection:
--  SELECT 1 FROM platform_admins pa JOIN users u ON u.id = pa.user_id )

-- Invariant B
SELECT o.id, o.name
  FROM identity.organizations o
 WHERE EXISTS (
         SELECT 1 FROM identity.organization_members om
           JOIN identity.users u ON u.id = om.user_id
          WHERE om.organization_id = o.id)
   AND NOT EXISTS (
         SELECT 1 FROM identity.organization_members om
           JOIN identity.users u ON u.id = om.user_id
           JOIN identity.role_templates rt ON rt.id = om.role_template_id
          WHERE om.organization_id = o.id
            AND (rt.scopes && ARRAY['admin','organizations:write']));
```

</details>

### Remediation

**Invariant B — an organization with no administrator.** Any platform
administrator can fix it through the API, no SQL required:

```bash
curl -X PUT "$REGISTRY/api/v1/organizations/$ORG_ID/members/$USER_ID" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"role_template_id":"'"$ORG_OWNER_TEMPLATE_ID"'"}'
```

(`$ORG_OWNER_TEMPLATE_ID` is the `org_owner` row of `GET /api/v1/admin/role-templates`.)
Alternatively remove the remaining members — an empty organization satisfies B.

**Invariant A — no platform administrator.** This one has no API route, because
every route that could grant it requires the `admin` scope nobody holds. It is
the one case that needs SQL, on the **registry** connection — and that SQL must
carry its own audit intent, because migration `000052` puts a deferred
constraint trigger on `platform_admins` that refuses any commit without one:

```sql
BEGIN;
WITH granted AS (
  -- Pick a user who can actually authenticate.
  INSERT INTO platform_admins (user_id, note)
  VALUES ('<user-uuid>', 'recovered after issue #766 detection')
  ON CONFLICT (user_id) DO NOTHING
  RETURNING user_id
)
INSERT INTO audit_outbox (event_id, action, resource_type, resource_id, metadata)
SELECT gen_random_uuid(), 'platform_admin.granted', 'platform_admin', g.user_id::text,
       jsonb_build_object('target_user_id', g.user_id, 'source', 'manual recovery')
  FROM granted g;
COMMIT;
```

Without the second statement the `COMMIT` fails with
`audit outbox: platform_admin.granted on ... has no audit intent in this
transaction`. `docs/configuration.md` documents the same requirement for
emergency SQL generally.

The change takes effect on that user's next request — the carrier is read per
request, not frozen into the token (`platform_admin_repository.go`). Verify with
`SELECT * FROM admin_floor_violations;` returning zero rows.

If identity lives in a separate database, confirm the user exists there first;
a `platform_admins` row naming a user the registry cannot resolve elevates
nobody and the floor will keep reporting the violation.

---

## Concurrency

Every check-then-write runs under one advisory lock
(`pg_advisory_xact_lock`) taken on the registry connection, scoped to a
transaction that carries no writes so the lock is released however the call
exits. A single deployment-wide lock rather than a per-organization one because
invariant A is deployment-wide and both invariants are decided by the same
reads — and because identity data may live on a different connection, where a
row lock taken here would reach nothing. These are rare administrative writes,
not a hot path.

`RevokePlatformAdmin` keeps its own, stricter refusal (`SELECT … FOR UPDATE`
over `platform_admins`, PR #862) and takes only the lock, so a carrier revoke
and a role-template demotion on the other connection cannot each observe the
other's administrator still standing.

**The floor's lock and the audit outbox do not interact.** `Serialize` holds a
write-free transaction open purely to scope `pg_advisory_xact_lock`; the carrier
mutation opens its *own* transaction, and that is the one migration `000052`'s
trigger examines for a matching `pg_current_xact_id()`. Every path that touches
`platform_admins` — the setup wizard's bootstrap grant, and the cleanups that
retire a deleted or erased principal's grant — writes its intent into that inner
transaction, so the grant and the record of it commit together or neither does.

The serialisation is proven against a real Postgres in
`backend/internal/adminfloor/adminfloor_postgres_test.go`, which forces the
interleaving rather than racing for it — it waits until Postgres itself reports
the second caller as blocked in `pg_locks` before releasing the first. Run it
with `TFR_TEST_DATABASE_URL` set.
