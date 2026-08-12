-- 000051_platform_admins
--
-- A carrier for platform-admin authority that is NOT an organization
-- membership (issue #766, PR 1 of 3).
--
-- Today the only carrier for the `admin` wildcard is
-- organization_members.role_template_id joined to an admin-bearing
-- role_templates row, and the org-less scope union makes that grant
-- platform-wide the moment it is held anywhere. #850 established the strongest
-- invariant reachable while that is true (an admin-bearing template becomes a
-- membership role only where a principal already holding platform-admin
-- authority put it there) and declined the recommendation to reject
-- admin-bearing templates on the member API -- because doing so would leave a
-- deployment unable to have a platform administrator at all.
--
-- This table is that missing carrier. PR 1 is deliberately NON-BREAKING:
-- effective admin is `carrier OR the existing scope union`, and the backfill
-- below makes the two sides agree on day one.
--
-- PROVENANCE, not a boolean. A table rather than users.is_platform_admin
-- because it records who granted the highest privilege in the product and
-- when -- exactly what an assessor asks about, and what a boolean throws away.
--
-- NO FOREIGN KEYS -- DELIBERATE, AND A DEVIATION FROM THE DESIGN COMMENT.
--
-- The design specified `user_id UUID PRIMARY KEY REFERENCES users(id) ON
-- DELETE CASCADE` and `granted_by UUID REFERENCES users(id) ON DELETE SET
-- NULL`. Those constraints cannot hold across the identity topologies this
-- product supports. This table is created by the REGISTRY's migrations on the
-- registry's own connection (public schema), while identity data may live in:
--
--   1. the registry's public schema      -- default; an FK would work
--   2. a shared `identity` schema        -- TFR_IDENTITY_SCHEMA_ENABLED; the
--      rows an FK must reference are in identity.users, and public.users
--      keeps only the pre-cutover copy (docs/identity-schema.md: identity
--      data is COPIED, not moved, so post-cutover users exist ONLY in
--      identity.users and an FK to public.users would refuse their grant)
--   3. a separate identity DATABASE      -- TFR_IDENTITY_DATABASE_*; Postgres
--      has no cross-database foreign keys at all
--
-- This is the same reasoning, and the same conclusion, as migration 000046
-- (user_token_revocations), which is likewise a per-user auth table on the
-- registry connection with no FK to users.
--
-- What the FKs would have bought is bounded and is handled elsewhere: user
-- IDs are UUIDs and are never reused, so a row left behind by a deleted user
-- grants nothing to anyone. Sweeping it belongs with the rest of the
-- credential lifecycle (internal/credlifecycle), which is where this estate
-- already does cross-connection cleanup that an FK cannot.
CREATE TABLE IF NOT EXISTS platform_admins (
    user_id     UUID PRIMARY KEY,
    granted_by  UUID,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    note        TEXT
);

-- BACKFILL -- every user who holds an admin-bearing role template today.
--
-- This is what makes PR 1 non-breaking in the other direction too: once PR 3
-- derives authority ONLY from the carrier, a deployment whose administrators
-- were never backfilled would have no platform administrator at all. The
-- cheapest moment to capture them is now, while both sources are still live.
--
-- granted_by is left NULL: nobody granted these, they are inferred. The note
-- says where each row came from so the provenance is not silently invented.
DO $$
DECLARE
  backfilled BIGINT;
BEGIN
  -- public.role_templates.scopes is jsonb (000001_initial_schema), so the
  -- admin-bearing test is jsonb containment.
  INSERT INTO platform_admins (user_id, note)
  SELECT DISTINCT om.user_id,
         'backfilled by migration 000051 from an admin-bearing role template on public.organization_members'
    FROM public.organization_members om
    JOIN public.role_templates rt ON rt.id = om.role_template_id
   WHERE om.user_id IS NOT NULL
     AND rt.scopes @> '["admin"]'::jsonb
  ON CONFLICT (user_id) DO NOTHING;
  GET DIAGNOSTICS backfilled = ROW_COUNT;
  IF backfilled > 0 THEN
    RAISE NOTICE 'migration 000051: backfilled % platform admin(s) from public.organization_members', backfilled;
  END IF;

  -- The identity-schema half. identity.role_templates.scopes is TEXT[], NOT
  -- jsonb (terraform-suite-identity 000001_identity_schema), so the same test
  -- is written differently -- and is guarded on the column actually still
  -- being an array, so a future identity schema change makes this block a
  -- no-op instead of failing startup.
  --
  -- Guarded on the tables existing, like migrations 000038/000045/000050, and
  -- with the same caveat: the schema literal `identity` is hardcoded, so a
  -- deployment that sets TFR_IDENTITY_SCHEMA_NAME to something else must edit
  -- this file or run the statement by hand.
  IF to_regclass('identity.organization_members') IS NOT NULL
     AND to_regclass('identity.role_templates') IS NOT NULL
     AND EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = 'identity'
                    AND table_name = 'role_templates'
                    AND column_name = 'scopes'
                    AND data_type = 'ARRAY') THEN
    INSERT INTO platform_admins (user_id, note)
    SELECT DISTINCT om.user_id,
           'backfilled by migration 000051 from an admin-bearing role template on identity.organization_members'
      FROM identity.organization_members om
      JOIN identity.role_templates rt ON rt.id = om.role_template_id
     WHERE om.user_id IS NOT NULL
       AND 'admin' = ANY(rt.scopes)
    ON CONFLICT (user_id) DO NOTHING;
    GET DIAGNOSTICS backfilled = ROW_COUNT;
    IF backfilled > 0 THEN
      RAISE NOTICE 'migration 000051: backfilled % platform admin(s) from identity.organization_members', backfilled;
    END IF;
  END IF;
END $$;

-- LIMITATION, stated rather than discovered later: when identity lives in a
-- SEPARATE DATABASE (TFR_IDENTITY_DATABASE_*), neither backfill above can see
-- it -- this migration runs on the registry's connection. Those deployments
-- must populate platform_admins by hand before PR 3 lands. Until then nothing
-- breaks: effective admin is carrier OR the scope union, and the union still
-- answers.
