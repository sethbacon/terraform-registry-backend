-- 000053_admin_floor_report
--
-- Detection and repair for the two never-zero administrator invariants
-- (issue #766, PR 3 of the #766 series):
--
--   A. the deployment always has at least one platform administrator
--   B. every organization with members has at least one member who can
--      administer it
--
-- The application now refuses every write that would break either one
-- (internal/adminfloor). This migration is about the deployments where they
-- are ALREADY broken, because nothing was stopping it until today.
--
-- ============================================================================
-- WHY THIS IS A REPORT AND NOT A CONSTRAINT
-- ============================================================================
--
-- Neither invariant is expressible as a constraint. Both are predicates over a
-- WHOLE TABLE ("at least one row exists such that..."), and CHECK constraints
-- are per-row. A trigger could express them, and would be wrong twice over:
--
--   1. It would fire on cascades. Deleting an organization removes its
--      memberships by ON DELETE CASCADE, and deleting a user removes theirs;
--      a trigger has no way to tell that from a member being offboarded, so it
--      would refuse operations the application deliberately allows.
--   2. It would forbid emptying an organization. Removing the last MEMBER is
--      legitimate -- an organization with nobody in it is the empty set, not a
--      stranded tenant -- while removing the last ADMINISTRATOR from an
--      organization that still has members is not. A row-level trigger sees
--      one DELETE and cannot distinguish them without re-querying the table it
--      is being fired from.
--
-- AND, DECISIVELY: a constraint or trigger would make an already-violating
-- deployment fail to start. `migrate up` runs before the server accepts
-- traffic, so a deployment whose only administrator was deleted last year --
-- exactly the deployment that most needs help -- would be unable to boot, and
-- the only fix would be hand-written SQL on the production database. That
-- trades a recoverable state for an unrecoverable one.
--
-- So: this migration REPORTS, REPAIRS WHAT IT SAFELY CAN, and never fails.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. REPAIR: re-run migration 000051's carrier backfill.
-- ----------------------------------------------------------------------------
--
-- 000051 captured every admin-bearing membership that existed AT THAT MOMENT.
-- The org-member API can still mint another one (an administrator granting the
-- `admin` role template to a colleague), and the setup wizard granted its
-- bootstrap administrator a membership and nothing else until this release.
-- Any of those has platform-admin authority through the scope union and NO
-- carrier row, so they vanish the day authority derives from the carrier alone.
--
-- Idempotent (ON CONFLICT DO NOTHING) and additive only. It never removes a
-- grant, so re-running it cannot reduce anybody's authority.
--
-- EVERY INSERT CARRIES ITS AUDIT INTENT, and it is not decoration. Migration
-- 000052 put a DEFERRABLE INITIALLY DEFERRED constraint trigger on
-- `platform_admins` that re-checks at COMMIT for an `audit_outbox` row with the
-- same pg_current_xact_id(), the same subject and action='platform_admin.granted'.
-- That trigger holds for migrations exactly as it holds for handlers -- which is
-- the point of it -- so 000051's backfill statement copied verbatim would abort
-- this migration at commit. It is written as a CTE so the intents are derived
-- from `RETURNING user_id`, i.e. from the rows ACTUALLY inserted: the ones
-- skipped by ON CONFLICT never fire the trigger and must not be given a record
-- of a grant that did not happen.
--
-- actor_user_id is NULL: nobody granted these, they are inferred from an
-- existing role template. That is the same statement 000051 makes with a NULL
-- `granted_by`, and the metadata says where the row came from so the provenance
-- is not silently invented.
DO $$
DECLARE
  backfilled BIGINT;
BEGIN
  WITH granted AS (
    INSERT INTO platform_admins (user_id, note)
    SELECT DISTINCT om.user_id,
           'backfilled by migration 000053 from an admin-bearing role template on public.organization_members'
      FROM public.organization_members om
      JOIN public.role_templates rt ON rt.id = om.role_template_id
     WHERE om.user_id IS NOT NULL
       AND rt.scopes @> '["admin"]'::jsonb
    ON CONFLICT (user_id) DO NOTHING
    RETURNING user_id
  )
  INSERT INTO audit_outbox (event_id, action, resource_type, resource_id, metadata)
  SELECT gen_random_uuid(), 'platform_admin.granted', 'platform_admin', g.user_id::text,
         jsonb_build_object(
           'target_user_id', g.user_id,
           'source', 'migration 000053 backfill',
           'origin', 'public.organization_members')
    FROM granted g;
  GET DIAGNOSTICS backfilled = ROW_COUNT;
  IF backfilled > 0 THEN
    RAISE NOTICE 'migration 000053: backfilled % platform admin(s) that postdate migration 000051', backfilled;
  END IF;

  -- The identity-schema half, guarded exactly as 000051 guards it: the shared
  -- identity schema stores role_templates.scopes as TEXT[], not jsonb, so the
  -- same predicate has to be written differently, and the guard makes a future
  -- schema change a no-op here instead of a failed startup.
  IF to_regclass('identity.organization_members') IS NOT NULL
     AND to_regclass('identity.role_templates') IS NOT NULL
     AND EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = 'identity'
                    AND table_name = 'role_templates'
                    AND column_name = 'scopes'
                    AND data_type = 'ARRAY') THEN
    WITH granted AS (
      INSERT INTO platform_admins (user_id, note)
      SELECT DISTINCT om.user_id,
             'backfilled by migration 000053 from an admin-bearing role template on identity.organization_members'
        FROM identity.organization_members om
        JOIN identity.role_templates rt ON rt.id = om.role_template_id
       WHERE om.user_id IS NOT NULL
         AND 'admin' = ANY(rt.scopes)
      ON CONFLICT (user_id) DO NOTHING
      RETURNING user_id
    )
    INSERT INTO audit_outbox (event_id, action, resource_type, resource_id, metadata)
    SELECT gen_random_uuid(), 'platform_admin.granted', 'platform_admin', g.user_id::text,
           jsonb_build_object(
             'target_user_id', g.user_id,
             'source', 'migration 000053 backfill',
             'origin', 'identity.organization_members')
      FROM granted g;
    GET DIAGNOSTICS backfilled = ROW_COUNT;
    IF backfilled > 0 THEN
      RAISE NOTICE 'migration 000053: backfilled % platform admin(s) from identity.organization_members', backfilled;
    END IF;
  END IF;
END $$;

-- ----------------------------------------------------------------------------
-- 2. DETECT: the standing operator query.
-- ----------------------------------------------------------------------------
--
--     SELECT * FROM admin_floor_violations;
--
-- Empty means both invariants hold. Every row is a state the application will
-- no longer let you REACH, but that it cannot retroactively undo.
--
-- SCOPE, STATED RATHER THAN DISCOVERED: this view reads the PUBLIC schema,
-- because that is the only schema this connection is guaranteed to have. A
-- deployment running TFR_IDENTITY_SCHEMA_ENABLED keeps its live membership
-- data in `identity.*` and only a pre-cutover copy in public, and a deployment
-- running TFR_IDENTITY_DATABASE_* keeps it in another database this migration
-- cannot see at all. In BOTH cases the view is answering about the wrong rows
-- and will report "no violations" whatever the truth is.
--
-- The identity-schema equivalent is the same query with `identity.` for
-- `public.` and `'admin' = ANY(rt.scopes)` for the jsonb containment tests
-- (scopes is TEXT[] there). Run it on the identity connection. The full text
-- is in docs/administrator-floor.md, which is also where the remediation steps
-- live.
CREATE OR REPLACE VIEW admin_floor_violations AS
-- Invariant A. One row, or none: the deployment either has an exercisable
-- platform administrator or it does not.
--
-- "Exercisable" means the grant resolves to a users row. An orphan carrier row
-- -- migration 000051 declines the foreign key that would prevent one, and
-- explains why it cannot have it -- elevates nobody, because both auth
-- middlewares load the user before consulting the carrier. Counting rows here
-- would report a healthy deployment that nobody can administer.
--
-- A deployment with NO USERS AT ALL is excluded, and that is not a loophole:
-- it is a database that has been migrated but not set up. The setup wizard has
-- not run, nobody has ever logged in, and there is nothing to remediate. Every
-- fresh install passes through that state, so reporting it would print the
-- alarming half of this migration on every first boot and teach operators to
-- ignore the warning that matters.
SELECT 'deployment'::TEXT     AS scope,
       NULL::UUID             AS organization_id,
       NULL::VARCHAR(255)     AS organization_name,
       'the deployment has no exercisable platform administrator'::TEXT AS violation
 WHERE EXISTS (SELECT 1 FROM public.users)
   AND NOT EXISTS (
         SELECT 1
           FROM public.platform_admins pa
           JOIN public.users u ON u.id = pa.user_id)
   AND NOT EXISTS (
         SELECT 1
           FROM public.organization_members om
           JOIN public.users u ON u.id = om.user_id
           JOIN public.role_templates rt ON rt.id = om.role_template_id
          WHERE rt.scopes @> '["admin"]'::jsonb)

UNION ALL

-- Invariant B. One row per stranded organization.
--
-- An organization with NO members is deliberately absent: it is the empty set,
-- the invariant is vacuous over it, and reporting it would bury the
-- organizations that genuinely cannot administer themselves under every
-- freshly created one. See internal/adminfloor's checkOrganizationFloor for
-- the same decision in the code that enforces it.
--
-- "Administrator" is `admin` or `organizations:write` -- the scope
-- RequireOrgScopeForPathOrg demands on every membership route, so an
-- organization with no holder of it cannot add, remove or re-role anybody.
SELECT 'organization'::TEXT,
       o.id,
       o.name,
       'organization has members but nobody who can administer it'::TEXT
  FROM public.organizations o
 WHERE EXISTS (
         SELECT 1
           FROM public.organization_members om
           JOIN public.users u ON u.id = om.user_id
          WHERE om.organization_id = o.id)
   AND NOT EXISTS (
         SELECT 1
           FROM public.organization_members om
           JOIN public.users u ON u.id = om.user_id
           JOIN public.role_templates rt ON rt.id = om.role_template_id
          WHERE om.organization_id = o.id
            AND (rt.scopes @> '["admin"]'::jsonb
                 OR rt.scopes @> '["organizations:write"]'::jsonb));

COMMENT ON VIEW admin_floor_violations IS
  'Issue #766: rows where a never-zero administrator invariant is already broken. '
  'Reads the public schema only -- see docs/administrator-floor.md for the '
  'identity-schema and identity-database equivalents, and for remediation.';

-- ----------------------------------------------------------------------------
-- 3. REPORT: say what was found, and do not fail.
-- ----------------------------------------------------------------------------
--
-- RAISE WARNING, never RAISE EXCEPTION. A violating deployment must still
-- start: the state is pre-existing, the application refuses to make it worse,
-- and an administrator has to be able to log in -- or the operator has to be
-- able to reach the API -- to repair it. Failing the migration would take away
-- the only route to the fix.
DO $$
DECLARE
  deployment_violations BIGINT;
  org_violations        BIGINT;
BEGIN
  SELECT count(*) FILTER (WHERE scope = 'deployment'),
         count(*) FILTER (WHERE scope = 'organization')
    INTO deployment_violations, org_violations
    FROM admin_floor_violations;

  IF deployment_violations > 0 THEN
    RAISE WARNING 'migration 000053: THIS DEPLOYMENT HAS NO PLATFORM ADMINISTRATOR. '
                  'Nobody can administer it through the API. Recover by inserting a row into '
                  'platform_admins for a user who can authenticate; see docs/administrator-floor.md.';
  END IF;

  IF org_violations > 0 THEN
    RAISE WARNING 'migration 000053: % organization(s) have members but no administrator. '
                  'Query `SELECT * FROM admin_floor_violations` and give each one a member '
                  'holding organizations:write; see docs/administrator-floor.md.', org_violations;
  END IF;

  IF deployment_violations = 0 AND org_violations = 0 THEN
    RAISE NOTICE 'migration 000053: both administrator invariants hold on the public schema.';
  END IF;
END $$;
