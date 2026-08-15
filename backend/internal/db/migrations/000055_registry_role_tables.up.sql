-- 000055_registry_role_tables
--
-- Registry's own per-app authorization tables (sethbacon/terraform-suite-identity#206,
-- phase "each app creates its per-app tables"; registry side, part A).
--
-- The target model is: identity is SHARED, authorization is PER-APP.
-- `organization_members` becomes the membership FACT only -- (organization_id,
-- user_id) -- and "which role does this member hold IN THIS APP" moves into the
-- app's own schema. These are registry's two tables for that.
--
-- THIS MIGRATION CHANGES NOTHING OBSERVABLE. Every read still comes from the
-- existing location (`organization_members.role_template_id` joined to
-- `role_templates`, wherever the connection's search_path puts them). The
-- application dual-writes into the tables below so that the read cutover, which
-- is a separate change, has a populated and continuously reconciled copy to
-- switch onto. Dropping `organization_members.role_template_id` is a LATER
-- phase and is explicitly not attempted here.
--
--
-- WHY `registry_role_templates` AND NOT `role_templates`
--
-- Because `public.role_templates` already exists, created by 000001, and in the
-- DEFAULT topology it IS the table registry reads role templates from. A second
-- table of the same name cannot be created beside it, and taking the name would
-- mean replacing the live one -- which is the read cutover, not this migration.
--
-- The duplicate `public.role_templates` is itself scheduled for removal in the
-- final phase of #206. When it goes, this table can take the unprefixed name.
-- Until then the prefix is what makes "registry's own copy" and "the shared
-- copy registry currently reads" distinguishable in the same schema, which is
-- the entire point of a dual-write phase.
--
-- `organization_member_roles` needs no prefix: registry has no table of that
-- name in any topology, so it takes the name #206 specifies.
--
--
-- NO FOREIGN KEYS TO IDENTITY -- DELIBERATE
--
-- `organization_member_roles.organization_id` and `.user_id` reference rows that
-- live in identity, and identity may be:
--
--   1. the registry's public schema      -- default; an FK would work
--   2. a shared `identity` schema        -- TFR_IDENTITY_SCHEMA_ENABLED; the
--      rows an FK must reference are in identity.organizations /
--      identity.users, while public.* keeps only the pre-cutover copy
--   3. a separate identity DATABASE      -- TFR_IDENTITY_DATABASE_*; Postgres
--      has no cross-database foreign keys at all
--
-- This table is created by REGISTRY's migrations on REGISTRY's connection, so
-- in topologies 2 and 3 an FK either targets the stale copy or cannot be
-- expressed at all. Same reasoning, and the same conclusion, as 000046
-- (user_token_revocations) and 000051 (platform_admins), which are likewise
-- per-user auth tables on the registry connection with no FK to identity.
--
-- The FK from `organization_member_roles.role_template_id` to
-- `registry_role_templates.id` IS expressible -- both tables are registry's own,
-- created together by this migration -- so it is declared, with ON DELETE SET
-- NULL to match the semantics `000001_initial_schema` gave the column it
-- mirrors: deleting a template clears the assignment, it does not delete the
-- membership.
--
--
-- NO BACKFILL HERE -- DELIBERATE, AND THE IMPORTANT PART
--
-- The rows to copy are "what registry resolves TODAY", and a migration running
-- on the registry connection cannot determine that. The effective source is
-- chosen at process start by the search_path of the identity pool
-- (cmd/server/main.go: TFR_IDENTITY_SCHEMA_ENABLED -> search_path
-- '<TFR_IDENTITY_SCHEMA_NAME>,public'), and by which DATABASE that pool dials
-- (TFR_IDENTITY_DATABASE_*). Neither is visible from SQL. Specifically:
--
--   * `INSERT ... SELECT FROM public.organization_members` is WRONG under
--     topology 2 -- public keeps only the pre-cutover copy, and the live rows
--     are in the identity schema.
--   * A `to_regclass('identity.organization_members') IS NOT NULL` probe does
--     not rescue it. That predicate is TRUE whenever the identity migrations
--     have run, including with TFR_IDENTITY_SCHEMA_ENABLED unset -- the state
--     where the identity schema is fully populated and receives no writes,
--     while public is still live. It is FALSE under topology 3, where the
--     identity schema exists in another database entirely and public again
--     holds only a stale copy.
--
-- In both of those a SQL backfill would silently capture the WRONG side. So the
-- backfill is not attempted here at all. It is done in Go, at startup, reading
-- through the very *sql.DB the application resolves role reads through
-- (`internal/db/repositories.ReconcileMemberRoles`), which makes the effective
-- source identical BY CONSTRUCTION rather than by inference -- and which
-- refuses, loudly, when that connection does not resolve the tables. It also
-- re-runs on every boot, so a deployment that upgrades before the tables exist
-- converges rather than staying half-populated.
--
-- Consequence, stated rather than discovered later: immediately after this
-- migration both tables are EMPTY. Nothing reads them yet, so that is not an
-- outage; it is the state the startup reconcile exists to resolve.
CREATE TABLE IF NOT EXISTS registry_role_templates (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description  TEXT,
    scopes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_system    BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- `scopes` is JSONB, not TEXT[]. Registry's own public.role_templates.scopes is
-- jsonb (000001), the identity schema's is jsonb from identity migration 000003
-- onwards, and the shared store's Go layer marshals the column as JSON in both.
-- One representation, and it is the one every reader already expects.
COMMENT ON TABLE registry_role_templates IS
    'Registry''s own role templates (terraform-suite-identity#206). Prefixed because public.role_templates still exists and is still what registry reads; the prefix goes when that duplicate does.';

-- One row per membership, INCLUDING memberships that carry no role
-- (role_template_id NULL). Faithful 1:1 with the source rather than
-- "rows only where a role exists", because a dual-write phase has to be able to
-- tell "this membership has no role here" apart from "this membership has not
-- been mirrored yet" -- and a detection query cannot distinguish those if the
-- absence of a row means both. The read cutover may collapse them; this phase
-- may not.
CREATE TABLE IF NOT EXISTS organization_member_roles (
    organization_id  UUID NOT NULL,
    user_id          UUID NOT NULL,
    role_template_id UUID REFERENCES registry_role_templates(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, user_id)
);

COMMENT ON TABLE organization_member_roles IS
    'Registry''s per-app role assignment for a shared membership (terraform-suite-identity#206). Written by the dual-write in internal/db/repositories; NOT yet read.';

CREATE INDEX IF NOT EXISTS idx_organization_member_roles_user
    ON organization_member_roles (user_id);
CREATE INDEX IF NOT EXISTS idx_organization_member_roles_role_template
    ON organization_member_roles (role_template_id);
