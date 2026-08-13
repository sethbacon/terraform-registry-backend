-- 000054_platform_admin_carrier_only
--
-- The close of issue #766, and the breaking half of the three-PR series:
-- platform-admin authority now derives ONLY from the `platform_admins` carrier
-- (migration 000051). The `admin` scope leaves the role templates, and the
-- application refuses to put it back on a membership.
--
-- ============================================================================
-- WHAT THE BINARY THAT SHIPS WITH THIS MIGRATION DOES
-- ============================================================================
--
--   * middleware.platformAdminScopes no longer ORs the carrier with the
--     session scope union. It STRIPS `admin` from a session whose principal has
--     no carrier row and adds it to one that does. `admin` on a role template
--     confers nothing from this release on.
--   * every membership write refuses an admin-bearing role template outright
--     (checkRoleAssignment / guardProvisionableRole) -- #766's headline
--     recommendation, unshippable in PR #850 because the template was then the
--     only carrier, shippable now because it is not.
--   * POST/PUT /api/v1/admin/role-templates refuse `admin` in `scopes`, so what
--     this migration removes cannot be reintroduced through the API.
--
-- ============================================================================
-- ORDER IS THE WHOLE POINT OF THIS FILE
-- ============================================================================
--
--   0. MEASURE, before anything is touched: does this deployment have an
--      exercisable platform administrator under the rule that is about to
--      change?
--   1. RE-RUN the carrier backfill. Migration 000051 captured the
--      administrators that existed when IT ran and 000053 captured those that
--      postdated it; anyone granted an admin-bearing template since then still
--      has no carrier row, and step 2 is the moment they would lose everything.
--   2. REMOVE `admin` from every role template.
--   3. ASSERT that an administrator survived, and REFUSE if one did not.
--
-- Steps must not be reordered and step 1 must not be skipped: it is the
-- difference between an upgrade and a lockout for every deployment that granted
-- the `admin` template between PR 1 and this release.
--
-- The whole file is one implicit transaction (golang-migrate sends it as a
-- single simple query), so the RAISE EXCEPTION in step 3 rolls the backfill and
-- the template edit back with it. A refused migration leaves the database
-- exactly as it was, on the previous binary, where the scope union still
-- answers -- a recoverable state. Proceeding would produce a deployment nobody
-- can administer, which is not. The schema_migrations row is left DIRTY: fix the
-- cause, `migrate force 53`, re-run.
--
-- WHAT `admin` IS REPLACED WITH, AND WHY IT IS NOT AN EMPTY LIST.
--
-- The wildcard conferred, among everything else, full administration of the
-- organizations the template was held in. Emptying the template would take that
-- away too and could leave an organization with members and nobody able to add,
-- remove or re-role anybody -- invariant B of the administrator floor, broken by
-- the very migration meant to be safe. So `admin` is replaced by exactly the
-- `org_owner` scope set (migration 000049): everything the template conferred
-- except the platform-wide reach, which has moved to the carrier. Holders keep
-- administering their organizations and stop administering the platform.
--
-- It applies to CUSTOM templates as well as the seeded one. A custom template
-- carrying `admin` is the same carrier for the same wildcard, and leaving it
-- would strand its holders on a role no membership write will accept again.

DO $$
DECLARE
  identity_here BOOLEAN := false;
  had_users     BOOLEAN := false;
  had_admin     BOOLEAN := false;  -- under the OLD rule: carrier OR the union
  has_admin     BOOLEAN := false;  -- under the NEW rule: the carrier alone
  backfilled    BIGINT;
  templates     BIGINT;
  org_owner_scopes CONSTANT jsonb :=
    '["organizations:write", "users:read", "api_keys:manage", "modules:read", "modules:write", "providers:read", "providers:write", "mirrors:read", "mirrors:manage", "scm:read", "scm:manage"]'::jsonb;
BEGIN
  -- --------------------------------------------------------------------------
  -- 0. MEASURE
  -- --------------------------------------------------------------------------
  --
  -- Every identity reference below sits inside `IF identity_here` because
  -- plpgsql plans a statement the first time it EXECUTES: a statement in a
  -- branch that is never taken is never planned, which is how migrations
  -- 000051 and 000053 reference `identity.*` on deployments that do not have
  -- it. A single statement mentioning both schemas would be planned -- and
  -- would fail -- on every default deployment.
  identity_here := to_regclass('identity.organization_members') IS NOT NULL
               AND to_regclass('identity.role_templates') IS NOT NULL
               AND to_regclass('identity.users') IS NOT NULL
               AND EXISTS (SELECT 1 FROM information_schema.columns
                            WHERE table_schema = 'identity'
                              AND table_name = 'role_templates'
                              AND column_name = 'scopes'
                              AND data_type = 'ARRAY');

  -- A database with no users has not been set up: the wizard has not run,
  -- nobody has ever logged in, and there is nothing to strand. Every fresh
  -- install passes through this state, so a refusal here would make a first
  -- boot impossible.
  SELECT EXISTS (SELECT 1 FROM public.users) INTO had_users;
  IF identity_here AND NOT had_users THEN
    SELECT EXISTS (SELECT 1 FROM identity.users) INTO had_users;
  END IF;

  -- "Exercisable", not merely recorded: a grant that resolves to no user row
  -- elevates nobody, because both auth middlewares load the user before
  -- consulting the carrier. Same rule migration 000053's admin_floor_violations
  -- view applies.
  SELECT EXISTS (
    SELECT 1 FROM public.platform_admins pa JOIN public.users u ON u.id = pa.user_id
     UNION ALL
    SELECT 1 FROM public.organization_members om
      JOIN public.users u ON u.id = om.user_id
      JOIN public.role_templates rt ON rt.id = om.role_template_id
     WHERE rt.scopes @> '["admin"]'::jsonb
  ) INTO had_admin;
  IF identity_here AND NOT had_admin THEN
    SELECT EXISTS (
      SELECT 1 FROM public.platform_admins pa JOIN identity.users u ON u.id = pa.user_id
       UNION ALL
      SELECT 1 FROM identity.organization_members om
        JOIN identity.users u ON u.id = om.user_id
        JOIN identity.role_templates rt ON rt.id = om.role_template_id
       WHERE 'admin' = ANY(rt.scopes)
    ) INTO had_admin;
  END IF;

  -- --------------------------------------------------------------------------
  -- 1. REPAIR: re-run the carrier backfill, one last time.
  -- --------------------------------------------------------------------------
  --
  -- Idempotent (ON CONFLICT DO NOTHING) and additive only; it never removes a
  -- grant, so re-running it cannot reduce anybody's authority.
  --
  -- EVERY INSERT CARRIES ITS AUDIT INTENT. Migration 000052 put a DEFERRABLE
  -- INITIALLY DEFERRED constraint trigger on `platform_admins` that re-checks
  -- at COMMIT for an `audit_outbox` row with the same pg_current_xact_id(), the
  -- same subject and action='platform_admin.granted'. It holds for migrations
  -- exactly as it holds for handlers, which is the point of it -- migration
  -- 000053 learned that by aborting at COMMIT with 000051's statement copied
  -- verbatim, and the CTE shape below is its fix: the intents are derived from
  -- `RETURNING user_id`, i.e. from the rows ACTUALLY inserted, so the ones
  -- skipped by ON CONFLICT are never given a record of a grant that did not
  -- happen.
  --
  -- actor_user_id is NULL: nobody granted these, they are inferred from a role
  -- template that is about to stop conferring anything.
  WITH granted AS (
    INSERT INTO platform_admins (user_id, note)
    SELECT DISTINCT om.user_id,
           'backfilled by migration 000054 before the admin scope left the role templates (public.organization_members)'
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
           'source', 'migration 000054 backfill',
           'origin', 'public.organization_members')
    FROM granted g;
  GET DIAGNOSTICS backfilled = ROW_COUNT;
  IF backfilled > 0 THEN
    RAISE NOTICE 'migration 000054: backfilled % platform admin(s) who would otherwise have lost the authority in this migration', backfilled;
  END IF;

  IF identity_here THEN
    WITH granted AS (
      INSERT INTO platform_admins (user_id, note)
      SELECT DISTINCT om.user_id,
             'backfilled by migration 000054 before the admin scope left the role templates (identity.organization_members)'
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
             'source', 'migration 000054 backfill',
             'origin', 'identity.organization_members')
      FROM granted g;
    GET DIAGNOSTICS backfilled = ROW_COUNT;
    IF backfilled > 0 THEN
      RAISE NOTICE 'migration 000054: backfilled % platform admin(s) from identity.organization_members', backfilled;
    END IF;
  END IF;

  -- --------------------------------------------------------------------------
  -- 2. REMOVE the wildcard from every role template.
  -- --------------------------------------------------------------------------

  -- The seeded template keeps its name and its holders and loses the wildcard.
  -- Its description is rewritten in the same statement: an entry still reading
  -- "Full access to all registry features" in the role-template picker would be
  -- a lie the moment this commits.
  UPDATE public.role_templates
     SET scopes      = org_owner_scopes,
         description = 'Full management of an organization''s modules, providers, mirrors, SCM integrations, and membership. Platform-wide administration is no longer carried by a role template -- it is granted through POST /api/v1/admin/platform-admins (issue #766)',
         updated_at  = NOW()
   WHERE name = 'admin'
     AND scopes @> '["admin"]'::jsonb;

  -- Every other template that carries the wildcard: `admin` out, the org_owner
  -- set in, everything else it already had kept.
  UPDATE public.role_templates rt
     SET scopes = COALESCE((
           SELECT jsonb_agg(d.s ORDER BY d.s)
             FROM (SELECT DISTINCT s FROM (
                     SELECT jsonb_array_elements_text(rt.scopes) AS s
                     UNION ALL
                     SELECT jsonb_array_elements_text(org_owner_scopes)
                   ) a
                   WHERE s <> 'admin') d), '[]'::jsonb),
         updated_at = NOW()
   WHERE rt.scopes @> '["admin"]'::jsonb;
  GET DIAGNOSTICS templates = ROW_COUNT;
  IF templates > 0 THEN
    RAISE NOTICE 'migration 000054: removed the admin wildcard from % further role template(s) on the public schema', templates;
  END IF;

  IF identity_here THEN
    UPDATE identity.role_templates
       SET scopes      = ARRAY(SELECT jsonb_array_elements_text(org_owner_scopes)),
           description = 'Full management of an organization''s modules, providers, mirrors, SCM integrations, and membership. Platform-wide administration is granted through POST /api/v1/admin/platform-admins (issue #766)',
           updated_at  = NOW()
     WHERE name = 'admin'
       AND 'admin' = ANY(scopes);

    UPDATE identity.role_templates rt
       SET scopes = COALESCE((
             SELECT array_agg(d.s ORDER BY d.s)
               FROM (SELECT DISTINCT s FROM (
                       SELECT unnest(rt.scopes) AS s
                       UNION ALL
                       SELECT jsonb_array_elements_text(org_owner_scopes)
                     ) a
                     WHERE s <> 'admin') d), ARRAY[]::TEXT[]),
           updated_at = NOW()
     WHERE 'admin' = ANY(rt.scopes);
  END IF;

  -- --------------------------------------------------------------------------
  -- 3. ASSERT: the two sources agreed, and somebody still administers this.
  -- --------------------------------------------------------------------------
  --
  -- This is the transition guard migration 000051 deferred to PR 3. It belongs
  -- here rather than in CI because the repo's tests run on sqlmock against no
  -- seeded database: only a real deployment's own data can answer it, and the
  -- only useful moment to ask is before the change commits.
  --
  -- WHAT IT ACTUALLY CATCHES, stated plainly rather than implied: step 1's
  -- backfill covers, by construction, every principal step 0 counted through
  -- the union -- so on a coherent deployment this refusal cannot fire, and that
  -- is the point. It fires when the backfill and the count DISAGREE: a
  -- predicate edited on one side and not the other, a schema this file half
  -- sees, a future identity layout where the two diverge. Delete the backfill
  -- and it fires immediately, which is how it is verified.
  --
  -- The carrier is resolved against BOTH user tables. Under
  -- TFR_IDENTITY_SCHEMA_ENABLED the live users are in identity.users and
  -- public.users holds only the pre-cutover copy, so counting public alone
  -- would report zero and refuse an upgrade that is perfectly safe.
  SELECT EXISTS (
    SELECT 1 FROM public.platform_admins pa JOIN public.users u ON u.id = pa.user_id
  ) INTO has_admin;
  IF identity_here AND NOT has_admin THEN
    SELECT EXISTS (
      SELECT 1 FROM public.platform_admins pa JOIN identity.users u ON u.id = pa.user_id
    ) INTO has_admin;
  END IF;

  IF had_users AND had_admin AND NOT has_admin THEN
    RAISE EXCEPTION
      'migration 000054 REFUSED: this deployment has a platform administrator today and would have none afterwards. '
      'Authority moves to the platform_admins carrier in this release and no row in it resolves to a user, so nobody '
      'could administer the deployment and no API route could grant it back. NOTHING HAS BEEN CHANGED. '
      'Grant the carrier by hand first -- docs/administrator-floor.md has the SQL, which must carry its own audit_outbox '
      'intent because of migration 000052''s constraint trigger -- verify with '
      '"SELECT pa.user_id FROM platform_admins pa JOIN users u ON u.id = pa.user_id", then "migrate force 53" and re-run.'
      USING ERRCODE = '23514',
            HINT = 'This means the backfill in step 1 and the count in step 0 disagree about who holds platform-admin authority. Read both before forcing past it.';
  END IF;

  -- Already broken before this file ran: not something 000054 caused, and
  -- refusing would take away the boot the repair needs. The same decision, for
  -- the same reason, migration 000053 made about pre-existing violations.
  IF had_users AND NOT has_admin THEN
    RAISE WARNING 'migration 000054: this deployment had no exercisable platform administrator before the migration ran, and still has none. '
                  'See docs/administrator-floor.md for the recovery SQL.';
  END IF;

  IF NOT had_users THEN
    -- One NOTICE covering two cases this connection genuinely cannot tell
    -- apart: a fresh install (the wizard writes the carrier directly), and a
    -- deployment whose identity lives in a SEPARATE DATABASE, which this
    -- migration cannot read at all -- migration 000051 states that limitation
    -- and this is the release in which it bites.
    RAISE NOTICE 'migration 000054: no users are visible on this connection. If this is a fresh install nothing is needed -- '
                 'the setup wizard writes the platform-admin carrier. If identity lives in a separate database '
                 '(TFR_IDENTITY_DATABASE_*), populate platform_admins by hand before starting this release; '
                 'see docs/administrator-floor.md.';
  ELSIF has_admin THEN
    RAISE NOTICE 'migration 000054: the admin scope has left the role templates; platform-admin authority is now carried by platform_admins alone.';
  END IF;
END $$;

-- ----------------------------------------------------------------------------
-- The operator's standing report, restated for carrier-only authority.
-- ----------------------------------------------------------------------------
--
-- Migration 000053 defined admin_floor_violations while effective admin was
-- `carrier OR union`, so its invariant A excused a deployment with no carrier
-- row as long as an admin-bearing membership existed. That excuse is now false:
-- the membership confers nothing, and leaving the clause in would report a
-- healthy deployment that nobody can administer -- the one thing this view
-- exists to catch.
--
-- Invariant B is UNCHANGED, including its `admin` disjunct. It asks who can
-- administer an ORGANIZATION; `admin` still answers that wherever it is
-- genuinely held, and no template can carry it any more, so the disjunct is
-- unreachable rather than wrong.
CREATE OR REPLACE VIEW admin_floor_violations AS
SELECT 'deployment'::TEXT     AS scope,
       NULL::UUID             AS organization_id,
       NULL::VARCHAR(255)     AS organization_name,
       'the deployment has no exercisable platform administrator'::TEXT AS violation
 WHERE EXISTS (SELECT 1 FROM public.users)
   AND NOT EXISTS (
         SELECT 1
           FROM public.platform_admins pa
           JOIN public.users u ON u.id = pa.user_id)

UNION ALL

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
  'Platform-admin authority is carrier-only from migration 000054, so invariant A '
  'counts platform_admins alone. Reads the public schema only -- see '
  'docs/administrator-floor.md for the identity-schema and identity-database '
  'equivalents, and for remediation.';
