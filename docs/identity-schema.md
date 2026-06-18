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

## Cross-schema foreign keys (resolved in backend 2.0)

> **Read this before enabling the cutover on a registry with module/provider data.**

The cutover routes **identity** data to the `identity` schema. In backend 2.0, migration
`000038_feature_fk_to_identity` automatically repoints the registry's **feature**-table
foreign keys from `public.{users,organizations}` to `identity.{users,organizations}`.
This is guarded — it only executes when the `identity` schema exists (cutover deployments)
and is a no-op otherwise. It is idempotent and fully reversible (the `.down.sql` repoints
back to `public`).

After the migration, feature writes by users/orgs created **after** the cutover work
correctly — the FK now resolves against `identity.users` / `identity.organizations`
where those rows live.

### Caveats

1. **Non-default schema name.** If you set `TFR_IDENTITY_SCHEMA_NAME` to something other
   than `identity`, the migration's hardcoded schema literal will not match. Edit the
   `.up.sql` and `.down.sql` files to replace `identity.` with your custom schema name
   before applying.

2. **Identity enabled after initial migration.** If you enable
   `TFR_IDENTITY_MIGRATIONS_ENABLED` on a deployment whose app migrations already ran
   (i.e. migration 000038 already executed as a no-op), golang-migrate will not re-run
   it. In this case, run the body of `000038_feature_fk_to_identity.up.sql` manually
   against the database — the SQL is safe to execute by hand (idempotent
   `DROP CONSTRAINT IF EXISTS` + `ADD CONSTRAINT`).

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

## See also

- `docs/configuration.md` — the full environment-variable reference.
- [ADR 012](adr/012-shared-identity-component.md) (shared identity component) in the registry and state-manager repositories.
