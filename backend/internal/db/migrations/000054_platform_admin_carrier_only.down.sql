-- Reverts the carrier-only authority model (issue #766).
--
-- PARTIAL, AND DELIBERATELY SO. Three things happened in the up migration and
-- only two of them can be undone.
--
-- 1. RESTORED: the seeded `admin` role template gets its `["admin"]` scope and
--    its description back. Roll the BINARY back first -- 4.x resolves effective
--    admin as `carrier OR the scope union`, so restoring the template returns
--    exactly the authority its holders had before the upgrade. Restoring it
--    while the new binary is running achieves nothing: that binary strips
--    `admin` from any session whose principal has no carrier row.
--
-- 2. RESTORED: migration 000053's admin_floor_violations definition, whose
--    invariant A counts the carrier OR an admin-bearing membership -- correct
--    again once the union confers authority again.
--
-- 3. NOT RESTORED: custom (non-system) role templates that carried `admin`.
--    The up migration replaced the wildcard with the `org_owner` scope set and
--    kept no record of which templates had it, because the audit trail for
--    authority is `platform_admins` and the outbox, not the template table.
--    Every holder of such a template was backfilled into the carrier by step 1
--    of the up migration, so nobody lost authority -- but if you want the
--    template itself to read `admin` again, add it by hand:
--
--      UPDATE role_templates SET scopes = scopes || '["admin"]'::jsonb
--       WHERE name = '<template>' AND NOT scopes @> '["admin"]'::jsonb;
--
--    The API will not do it for you in either direction: from 000054 the
--    role-template endpoints refuse `admin` in `scopes`.
--
-- THE BACKFILLED CARRIER GRANTS ARE LEFT IN PLACE, on migration 000053's
-- reasoning: deleting them would strip real authority from real people on a
-- rollback, and they are harmless under the old binary, where a carrier row for
-- somebody who also holds it through the union changes nothing. Find them with
--
--   SELECT user_id, granted_at, note FROM platform_admins
--    WHERE note LIKE 'backfilled by migration 000054%';

UPDATE role_templates
   SET scopes      = '["admin"]'::jsonb,
       description = 'Full access to all registry features',
       updated_at  = NOW()
 WHERE name = 'admin'
   AND is_system
   AND NOT scopes @> '["admin"]'::jsonb;

DO $$
BEGIN
  IF to_regclass('identity.role_templates') IS NOT NULL
     AND EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema = 'identity'
                    AND table_name = 'role_templates'
                    AND column_name = 'scopes'
                    AND data_type = 'ARRAY') THEN
    UPDATE identity.role_templates
       SET scopes      = ARRAY['admin']::TEXT[],
           description = 'Full access to all registry features',
           updated_at  = NOW()
     WHERE name = 'admin'
       AND is_system
       AND NOT ('admin' = ANY(scopes));
  END IF;
END $$;

-- Migration 000053's definition, verbatim apart from this comment.
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
   AND NOT EXISTS (
         SELECT 1
           FROM public.organization_members om
           JOIN public.users u ON u.id = om.user_id
           JOIN public.role_templates rt ON rt.id = om.role_template_id
          WHERE rt.scopes @> '["admin"]'::jsonb)

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
  'Reads the public schema only -- see docs/administrator-floor.md for the '
  'identity-schema and identity-database equivalents, and for remediation.';
