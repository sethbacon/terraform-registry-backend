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

**Platform administrator** — a principal holding a row in `platform_admins`
(the carrier, migration `000051`). Nothing else, as of migration `000054`.

An organization membership whose role template carries the `admin` scope used to
count too, through the org-less scope union (#652). It does not any more: the
auth middleware strips `admin` from the session union, so such a membership
administers nothing, and a floor that still counted one would report "an
administrator remains" while the deployment's last real one was deleted.

Two consequences follow, and both are behaviour you can observe:

- **A membership change cannot break invariant A.** Removing a member, re-roling
  one, or deleting an organization does not touch `platform_admins`. Only user
  deletion and GDPR erasure can, by making a carrier grant unexercisable.
- **Deleting a principal who holds no carrier row is never refused by invariant
  A**, because it cannot lower the count.

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

The setup wizard (`POST /api/v1/setup/admin`) writes the `platform_admins` row
and **nothing else**. It used to write an `admin` role-template membership as
well; migration `000054` removed that, because a role template confers no
platform-admin authority any more and it was the last path by which the
platform-wide wildcard reached `organization_members` at all.

The bootstrap administrator therefore starts with **no organization
membership**. That is not a gap: the carrier grants the `admin` wildcard on
every request, which every organization route already accepts, and invariant B
is vacuous over an organization with no members. They can enrol themselves, or
anyone else, through the member API immediately.

If the carrier grant fails — the registry connection is down while the identity
connection is up — **setup fails with `500`**. It used to report
`platform_admin_carrier_incomplete: true` beside a `200`, on the grounds that
the membership already conferred the authority. There is no membership now, so a
clean `200` would leave a deployment with no administrator and no API route able
to create one. Setup has not been marked complete at that point: fix the
connection and retry.

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
-- Invariant A is entirely on the REGISTRY connection from migration 000054 --
-- the carrier is the only source -- but the users it resolves against live in
-- the identity schema, so it is the one query that spans both:
--   registry: SELECT user_id FROM platform_admins;
--   identity: SELECT id FROM identity.users WHERE id = ANY(<those ids>);
-- an empty intersection is the violation.

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
every route that could grant it requires the `admin` scope nobody holds — and
from migration `000054` there is no role template to grant either, so this SQL
is the *only* recovery. It runs on the **registry** connection, and it must
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
request, not frozen into the token (`identity/platformadmin`, instantiated in
`internal/api/router.go` against `platform_admins`). Verify with
`SELECT * FROM admin_floor_violations;` returning zero rows.

If identity lives in a separate database, confirm the user exists there first;
a `platform_admins` row naming a user the registry cannot resolve elevates
nobody and the floor will keep reporting the violation.

---

## Concurrency

Every check-then-write runs under one advisory lock
(`pg_advisory_xact_lock`) taken on the registry connection, scoped to a
transaction that carries no writes so the lock is released however the call
exits. A single application-wide lock rather than a per-organization one because
invariant A is application-wide and both invariants are decided by the same
reads — and because identity data may live on a different connection, where a
row lock taken here would reach nothing. These are rare administrative writes,
not a hot path.

The lock is the carrier's (`identity/platformadmin`), and its key is derived
from the carrier's qualified table name rather than being a constant. That is
what keeps two applications sharing one database — the deployment the suite
identity model is built for — from serialising against each other's unrelated
administrator changes. It also means the name must be spelled the same way in
every process: `internal/api/router.go` holds the single spelling
(`platformAdminTable`), and a process that constructed the carrier as
`public.platform_admins` would address the same table under a different lock.

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

---

## Migration `000054` can refuse to apply

This is the migration that makes platform-admin authority carrier-only, and it
runs three things in order: it re-runs the carrier backfill from any
admin-bearing role template it can see, then removes `admin` from every role
template, then asserts an administrator survived.

If the assertion fails it raises, which rolls the whole migration back — the
templates are untouched, no carrier row was added, and the deployment is exactly
as it was, on the previous binary, where the scope union still answers. The
`schema_migrations` row is left **dirty**.

```txt
migration 000054 REFUSED: this deployment has a platform administrator today and
would have none afterwards. ... NOTHING HAS BEEN CHANGED.
```

The recovery is the invariant-A SQL above: grant `platform_admins` by hand to a
user who can authenticate, verify with

```sql
SELECT pa.user_id FROM platform_admins pa JOIN users u ON u.id = pa.user_id;
```

then `migrate force 53` and run the upgrade again.

**On a coherent deployment this refusal cannot fire**, because step 1's backfill
covers by construction everybody step 0 counted. It fires when the two disagree
— a predicate edited on one side only, or a schema layout the migration half
sees. Read both before forcing past it.

**A deployment whose identity lives in a separate database
(`TFR_IDENTITY_DATABASE_*`) is the case no assertion on this connection can
make.** The migration cannot see those users or memberships at all — migration
`000051` states the limitation and this is the release in which it bites — so it
emits a NOTICE and proceeds. Populate `platform_admins` by hand, with the SQL
above, **before** starting this release.
