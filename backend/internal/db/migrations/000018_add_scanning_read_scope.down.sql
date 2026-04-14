-- 000018_add_scanning_read_scope.down.sql
-- Remove scanning:read scope from devops and auditor system role templates.

UPDATE role_templates
SET scopes = scopes - 'scanning:read'
WHERE name = 'devops' AND is_system = true;

UPDATE role_templates
SET scopes = scopes - 'scanning:read'
WHERE name = 'auditor' AND is_system = true;
