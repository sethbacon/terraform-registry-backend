-- 000059_group_mappings
--
-- Registry's own per-app group-mapping table (sethbacon/terraform-suite-identity#206,
-- phase 2: "each app creates its per-app tables and backfills"; registry side).
--
-- The target model is: identity is SHARED, authorization is PER-APP. An IdP
-- group mapping is authorization policy -- "members of IdP group G get THIS
-- APP's role R in organization O" -- so #206 places it in the app's own schema
-- as `<app>.group_mappings`, next to `registry_role_templates` and
-- `organization_member_roles` (migration 000055).
--
-- THIS MIGRATION CHANGES NOTHING OBSERVABLE. Group mappings are read today
-- from `oidc_config.extra_config` on the identity connection (keys
-- `group_claim_name`, `group_mappings`, `default_role`; see
-- resolveGroupMappingConfig in internal/api/admin/auth.go), with an env/file
-- fallback. Every read keeps coming from there. The application dual-writes
-- the mapping rows below so that the read cutover, which is a separate change,
-- has a populated and continuously reconciled copy to switch onto.
--
--
-- WHERE GROUP MAPPINGS LIVE TODAY, PRECISELY
--
-- There is no `oidc_group_mappings` table anywhere in the suite. The mappings
-- are a JSON list inside the `extra_config` JSONB column of `oidc_config` --
-- one ordered list per OIDC provider configuration, of which at most one is
-- active. Order is LOAD-BEARING: the shared library's ResolveGroupMappings
-- resolves competing mappings first-match-wins in configuration order
-- (terraform-suite-identity#269), which is why this table has a `position`
-- column and why its primary key includes it.
--
-- The SAML and LDAP group mappings are env/file configuration only -- they
-- have no database write sites, so a dual-write phase has nothing to mirror
-- for them. How they enter this table (probably as seeded rows) is the read
-- cutover's decision, not this migration's.
--
-- `group_claim_name` and `default_role` are per-provider-config settings, not
-- mapping rows; they stay in `oidc_config.extra_config` with the rest of the
-- provider configuration. #206 assigns only the group->role rows to the app.
--
--
-- WHY `group_mappings` AND NOT `registry_group_mappings`
--
-- 000055 prefixed `registry_role_templates` for exactly one reason: a live
-- `public.role_templates` already existed and taking the name would have BEEN
-- the read cutover. No table named `group_mappings` exists in any topology --
-- not in registry's public schema, not in the identity schema -- so, by the
-- same rule that gave `organization_member_roles` its unprefixed name, this
-- table takes the name #206 specifies.
--
--
-- COLUMNS, AND THE ONE REAL FOREIGN KEY
--
-- `oidc_config_id` points at the `oidc_config` row whose extra_config carries
-- the source list. That row lives on the IDENTITY connection -- possibly a
-- different schema, possibly a different DATABASE (TFR_IDENTITY_DATABASE_*) --
-- so the reference carries NO foreign key, same reasoning as 000046, 000051,
-- 000055 and 000056. Rows are mirrored for EVERY config, not just the active
-- one: which config is active stays `oidc_config`'s own fact, and a mirror
-- that second-guessed it could not be compared row-for-row against its source.
--
-- `organization_name` names an identity organization BY NAME, because that is
-- what the stored mappings carry (the {group, organization, role} triple) and
-- what the login-time reconciliation resolves. It points across the identity
-- boundary, so again: no foreign key.
--
-- `role_template_name` is the faithful copy of the stored string. It is kept
-- verbatim because a mapping may legitimately name a template that does not
-- (yet, or any longer) resolve -- today that mapping simply confers nothing at
-- login (see guardProvisionableRole), and a mirror that dropped or rejected
-- such a row could not be compared 1:1 against its source.
--
-- `role_template_id` is the app-local resolution of that name, and it is the
-- one REAL foreign key here: registry_role_templates is registry's own table,
-- created by 000055 on this same connection, and since the phase-3b read
-- cutover it is what every role and scope set actually comes from. NULL means
-- "the name does not currently resolve". ON DELETE SET NULL mirrors what
-- deleting a template does to that mapping's effect at login: the mapping
-- stays configured, it just confers nothing. The dual-write re-resolves the
-- name on every mirror write and the boot reconcile re-resolves it on every
-- boot, so a template created AFTER a mapping that names it converges.
--
--
-- NO BACKFILL HERE -- SAME REASONING AS 000055, STRONGER
--
-- The source rows live in `oidc_config`, which this migration -- running on
-- the REGISTRY connection -- may not even be able to see: under
-- TFR_IDENTITY_SCHEMA_ENABLED the live rows are in the identity schema while
-- public keeps a pre-cutover copy, and under TFR_IDENTITY_DATABASE_* they are
-- in another database entirely. A SQL backfill would silently capture the
-- wrong side in both. The backfill is therefore done in Go, at startup,
-- reading through the very connection the application resolves OIDC-config
-- reads through (internal/db/repositories.ReconcileGroupMappings), which makes
-- the effective source identical BY CONSTRUCTION. It re-runs on every boot, so
-- a deployment that upgrades before this table exists converges rather than
-- staying half-populated.
--
-- Consequence, stated rather than discovered later: immediately after this
-- migration the table is EMPTY. Nothing reads it yet, so that is not an
-- outage; it is the state the startup reconcile exists to resolve.
CREATE TABLE IF NOT EXISTS group_mappings (
    oidc_config_id     UUID NOT NULL,
    position           INTEGER NOT NULL CHECK (position >= 0),
    group_name         TEXT NOT NULL,
    organization_name  TEXT NOT NULL,
    role_template_name TEXT NOT NULL,
    role_template_id   UUID REFERENCES registry_role_templates(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (oidc_config_id, position)
);

-- No updated_at: rows are replaced wholesale. A change to a config's mapping
-- list deletes and re-inserts that config's rows in one transaction (the list
-- is small and ordered, and positions shift on any edit), so a per-row
-- updated_at could never differ from created_at.
COMMENT ON TABLE group_mappings IS
    'Registry''s own IdP group -> role-template mappings (terraform-suite-identity#206). Mirrors the group_mappings list in oidc_config.extra_config; written by the dual-write in internal/db/repositories and the boot reconcile; NOT yet read.';

CREATE INDEX IF NOT EXISTS idx_group_mappings_role_template
    ON group_mappings (role_template_id);
