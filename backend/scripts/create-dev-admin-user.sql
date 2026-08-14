-- Create a dev admin user, assign to the default organization, and grant
-- platform-admin through the carrier.
--
-- Run this inside the postgres container or via psql.
--
-- WHY THE CARRIER GRANT IS HERE, not implied by the role template:
--
-- Migration 000054 (issue #766) took the `admin` wildcard scope off every role
-- template. Platform-admin authority now comes ONLY from a `platform_admins`
-- row, resolved per request. The `admin` template still exists and still grants
-- organization administration (the org_owner scope set), but it no longer
-- confers platform-wide reach and notably no longer implies `audit:read`.
--
-- 000054 backfilled a carrier row for everyone who held an admin-bearing
-- template WHEN IT RAN. A fresh stack runs migrations against an empty database
-- and seeds afterwards, so this user postdates the backfill and gets nothing
-- from it. Without the grant below, dev login succeeds, /admin renders, and
-- then every platform-scoped read (audit logs first) fails -- which is exactly
-- how this surfaced: the frontend E2E suite went red on "Audit Logs page
-- (authenticated)" while every unauthenticated test passed.
--
-- The grant is made HERE, at provisioning, rather than in DevLoginHandler.
-- Minting a carrier row at login would make DEV_MODE a way to become a platform
-- administrator with no grant on record, which is the property the carrier
-- exists to provide. Seeding is a deliberate provisioning act; logging in is not.
DO $$
DECLARE
    v_user_id uuid;
    v_org_id uuid;
    v_admin_role_template_id uuid;
    v_granted integer;
BEGIN
    -- Insert dev admin user
    INSERT INTO users (email, name, oidc_sub)
    VALUES ('admin@dev.local', 'Dev Admin', 'dev-admin-oidc-sub')
    ON CONFLICT (email) DO NOTHING;

    -- Get user id
    SELECT id INTO v_user_id FROM users WHERE email = 'admin@dev.local';
    RAISE NOTICE 'User ID: %', v_user_id;

    -- Get default organization id
    SELECT id INTO v_org_id FROM organizations WHERE name = 'default';
    RAISE NOTICE 'Default Org ID: %', v_org_id;

    -- Get admin role template id
    SELECT id INTO v_admin_role_template_id FROM role_templates WHERE name = 'admin';
    RAISE NOTICE 'Admin Role Template ID: %', v_admin_role_template_id;

    -- Insert org membership with the admin role. Post-000054 this template is
    -- not admin-bearing, so the membership guard accepts it.
    INSERT INTO organization_members (organization_id, user_id, role_template_id)
    VALUES (v_org_id, v_user_id, v_admin_role_template_id)
    ON CONFLICT (organization_id, user_id) DO UPDATE SET role_template_id = EXCLUDED.role_template_id;

    -- Grant platform-admin via the carrier, with its audit record written in the
    -- SAME transaction. Migration 000052 puts a DEFERRABLE INITIALLY DEFERRED
    -- constraint trigger on platform_admins that re-checks at COMMIT for an
    -- audit_outbox intent carrying the same pg_current_xact_id(), subject and
    -- action -- so a bare INSERT here would abort the whole script at COMMIT.
    -- ON CONFLICT DO NOTHING keeps this idempotent, and the intent is derived
    -- from RETURNING so a re-run that inserts nothing also records nothing.
    WITH granted AS (
        INSERT INTO platform_admins (user_id, note)
        VALUES (v_user_id, 'granted by scripts/create-dev-admin-user.sql (development seed)')
        ON CONFLICT (user_id) DO NOTHING
        RETURNING user_id
    )
    INSERT INTO audit_outbox (event_id, action, resource_type, resource_id, metadata)
    SELECT gen_random_uuid(), 'platform_admin.granted', 'platform_admin', g.user_id::text,
           jsonb_build_object(
             'target_user_id', g.user_id,
             'source', 'scripts/create-dev-admin-user.sql',
             'origin', 'development seed')
      FROM granted g;
    GET DIAGNOSTICS v_granted = ROW_COUNT;

    IF v_granted > 0 THEN
        RAISE NOTICE 'Platform-admin carrier row granted to admin@dev.local.';
    ELSE
        RAISE NOTICE 'admin@dev.local already holds a platform-admin carrier row; nothing to grant.';
    END IF;

    -- Dev login now uses JWT via POST /api/v1/dev/login (no hardcoded API key needed)
    RAISE NOTICE 'Dev admin user, org membership, and platform-admin carrier row are in place.';
END $$;
