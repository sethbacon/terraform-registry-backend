-- 000018_add_scanning_read_scope.up.sql
-- Add scanning:read scope to devops and auditor system role templates
-- so they can view scan results and stats without full admin access.

UPDATE role_templates
SET scopes = scopes || '["scanning:read"]'::jsonb
WHERE name = 'devops' AND is_system = true;

UPDATE role_templates
SET scopes = scopes || '["scanning:read"]'::jsonb
WHERE name = 'auditor' AND is_system = true;
