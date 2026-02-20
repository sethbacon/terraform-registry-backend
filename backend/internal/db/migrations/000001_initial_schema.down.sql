-- Drop all tables in reverse FK dependency order.
-- CASCADE handles any remaining dependent objects (indexes, constraints, etc.).

-- Storage
DROP TABLE IF EXISTS storage_config CASCADE;
DROP TABLE IF EXISTS system_settings CASCADE;

-- RBAC: policies and approval workflows
DROP TABLE IF EXISTS mirror_policies CASCADE;
DROP TABLE IF EXISTS mirror_approval_requests CASCADE;

-- Mirroring: version tracking, provider tracking, sync history, configurations
DROP TABLE IF EXISTS mirrored_provider_versions CASCADE;
DROP TABLE IF EXISTS mirrored_providers CASCADE;
DROP TABLE IF EXISTS mirror_sync_history CASCADE;
DROP TABLE IF EXISTS mirror_configurations CASCADE;

-- Analytics
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS download_events CASCADE;

-- SCM: immutability violations, webhook events
DROP TABLE IF EXISTS version_immutability_violations CASCADE;
DROP TABLE IF EXISTS scm_webhook_events CASCADE;

-- Registry: platforms, versions
DROP TABLE IF EXISTS provider_platforms CASCADE;
DROP TABLE IF EXISTS provider_versions CASCADE;
DROP TABLE IF EXISTS module_versions CASCADE;

-- SCM: repos and OAuth tokens (after module_versions which references module_scm_repos)
DROP TABLE IF EXISTS module_scm_repos CASCADE;
DROP TABLE IF EXISTS scm_oauth_tokens CASCADE;
DROP TABLE IF EXISTS scm_providers CASCADE;

-- Registry: core resource tables
DROP TABLE IF EXISTS providers CASCADE;
DROP TABLE IF EXISTS modules CASCADE;

-- Auth
DROP TABLE IF EXISTS organization_members CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;
DROP TABLE IF EXISTS role_templates CASCADE;

-- Core
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
