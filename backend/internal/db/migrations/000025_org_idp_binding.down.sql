ALTER TABLE organizations
    DROP COLUMN IF EXISTS idp_type,
    DROP COLUMN IF EXISTS idp_name;
