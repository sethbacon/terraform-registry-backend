-- Create a dev admin user, assign to default organization, and grant admin role
-- Run this inside the postgres container or via psql
DO $$
DECLARE
    v_user_id uuid;
    v_org_id uuid;
    v_admin_role_template_id uuid;
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

    -- Insert org membership with admin role
    INSERT INTO organization_members (organization_id, user_id, role_template_id)
    VALUES (v_org_id, v_user_id, v_admin_role_template_id)
    ON CONFLICT (organization_id, user_id) DO UPDATE SET role_template_id = EXCLUDED.role_template_id;

    -- Dev login now uses JWT via POST /api/v1/dev/login (no hardcoded API key needed)
    RAISE NOTICE 'Dev admin user and org membership with admin role assigned.';
END $$;
