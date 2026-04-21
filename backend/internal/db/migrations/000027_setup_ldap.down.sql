-- 000027_setup_ldap.down.sql
ALTER TABLE system_settings
    DROP COLUMN IF EXISTS auth_method,
    DROP COLUMN IF EXISTS ldap_configured,
    DROP COLUMN IF EXISTS ldap_configured_at,
    DROP COLUMN IF EXISTS ldap_config;
