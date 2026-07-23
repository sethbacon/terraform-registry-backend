-- 000049_add_org_owner_provisioner_roles.up.sql
-- Add org_owner and org_provisioner system role templates (issue #648).
--
-- org_owner replaces the previous practice of auto-granting the
-- platform-wide admin role template to the creator of a new organization: it
-- grants full management of a single organization's modules, providers,
-- mirrors, SCM integrations, and membership, without the admin template's
-- global wildcard scope.
--
-- org_provisioner grants only the ability to create new top-level
-- organizations (organizations:create) plus read access, for operators who
-- need to provision orgs without full platform admin access.

INSERT INTO role_templates (name, display_name, description, scopes, is_system) VALUES
('org_owner',
 'Organization Owner',
 'Full management of a single organization''s modules, providers, mirrors, SCM integrations, and membership, without platform-wide admin privileges',
 '["organizations:write", "users:read", "api_keys:manage", "modules:read", "modules:write", "providers:read", "providers:write", "mirrors:read", "mirrors:manage", "scm:read", "scm:manage"]'::jsonb,
 true),
('org_provisioner',
 'Organization Provisioner',
 'Can provision new top-level organizations without platform-wide admin privileges',
 '["organizations:create", "organizations:read"]'::jsonb,
 true);
