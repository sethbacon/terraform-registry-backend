-- Per-org IdP binding: optional identity provider restriction per organization
ALTER TABLE organizations
    ADD COLUMN idp_type VARCHAR(50) DEFAULT NULL,
    ADD COLUMN idp_name VARCHAR(255) DEFAULT NULL;

COMMENT ON COLUMN organizations.idp_type IS 'IdP type: oidc, saml, or ldap. NULL means no restriction.';
COMMENT ON COLUMN organizations.idp_name IS 'IdP name within the type (e.g., SAML IdP name). NULL means no restriction.';
