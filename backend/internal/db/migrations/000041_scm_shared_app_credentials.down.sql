-- Reverse migration 000041. Refuses to run while any provider is still in an app
-- auth mode, since dropping the columns would silently destroy the only copy of
-- those providers' app credentials. Convert such providers back to 'oauth_user'
-- (clearing their app fields) before rolling back.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM scm_providers WHERE auth_mode IN ('entra_app', 'github_app')) THEN
        RAISE EXCEPTION 'cannot roll back 000041: providers still use an app auth_mode; convert them to oauth_user first';
    END IF;
END $$;

DROP TABLE IF EXISTS scm_provider_tokens;

ALTER TABLE scm_providers DROP CONSTRAINT IF EXISTS scm_providers_app_shape;
ALTER TABLE scm_providers DROP COLUMN IF EXISTS encrypted_app_private_key;
ALTER TABLE scm_providers DROP COLUMN IF EXISTS github_installation_id;
ALTER TABLE scm_providers DROP COLUMN IF EXISTS github_app_id;
ALTER TABLE scm_providers DROP COLUMN IF EXISTS auth_mode;
