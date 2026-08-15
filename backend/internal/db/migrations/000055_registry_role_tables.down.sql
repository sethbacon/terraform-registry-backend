-- Drops registry's per-app authorization tables (terraform-suite-identity#206).
--
-- Safe while nothing reads them. Every row in both tables is DERIVED -- either
-- dual-written alongside the authoritative write to `organization_members` /
-- `role_templates`, or reconciled from those at startup -- so dropping them
-- removes no authority from anybody and changes no authorization decision.
--
-- That stops being true the moment the read cutover ships: from then on these
-- ARE the authorization tables and this file destroys them. Roll the binary
-- back first.
DROP TABLE IF EXISTS organization_member_roles;
DROP TABLE IF EXISTS registry_role_templates;
