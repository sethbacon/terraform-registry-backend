-- 000049_add_org_owner_provisioner_roles.down.sql
-- Remove the org_owner and org_provisioner system role templates.

DELETE FROM role_templates WHERE name IN ('org_owner', 'org_provisioner') AND is_system = true;
