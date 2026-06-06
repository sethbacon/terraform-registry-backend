-- Repoint feature-table foreign keys from public.{users,organizations} to
-- identity.{users,organizations} so identities created after the identity-schema
-- cutover can perform feature writes. No-op when the identity schema is absent
-- (default, non-cutover deployments). See docs/identity-schema.md.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity') THEN
    ALTER TABLE public.download_events DROP CONSTRAINT IF EXISTS download_events_user_id_fkey;
    ALTER TABLE public.download_events ADD CONSTRAINT download_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES identity.users(id);

    ALTER TABLE public.mirror_approval_requests DROP CONSTRAINT IF EXISTS mirror_approval_requests_organization_id_fkey;
    ALTER TABLE public.mirror_approval_requests ADD CONSTRAINT mirror_approval_requests_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id) ON DELETE CASCADE;

    ALTER TABLE public.mirror_approval_requests DROP CONSTRAINT IF EXISTS mirror_approval_requests_requested_by_fkey;
    ALTER TABLE public.mirror_approval_requests ADD CONSTRAINT mirror_approval_requests_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES identity.users(id) ON DELETE SET NULL;

    ALTER TABLE public.mirror_approval_requests DROP CONSTRAINT IF EXISTS mirror_approval_requests_reviewed_by_fkey;
    ALTER TABLE public.mirror_approval_requests ADD CONSTRAINT mirror_approval_requests_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES identity.users(id) ON DELETE SET NULL;

    ALTER TABLE public.mirror_configurations DROP CONSTRAINT IF EXISTS mirror_configurations_created_by_fkey;
    ALTER TABLE public.mirror_configurations ADD CONSTRAINT mirror_configurations_created_by_fkey FOREIGN KEY (created_by) REFERENCES identity.users(id) ON DELETE SET NULL;

    ALTER TABLE public.mirror_configurations DROP CONSTRAINT IF EXISTS mirror_configurations_organization_id_fkey;
    ALTER TABLE public.mirror_configurations ADD CONSTRAINT mirror_configurations_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id) ON DELETE CASCADE;

    ALTER TABLE public.mirror_policies DROP CONSTRAINT IF EXISTS mirror_policies_created_by_fkey;
    ALTER TABLE public.mirror_policies ADD CONSTRAINT mirror_policies_created_by_fkey FOREIGN KEY (created_by) REFERENCES identity.users(id) ON DELETE SET NULL;

    ALTER TABLE public.mirror_policies DROP CONSTRAINT IF EXISTS mirror_policies_organization_id_fkey;
    ALTER TABLE public.mirror_policies ADD CONSTRAINT mirror_policies_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id) ON DELETE CASCADE;

    ALTER TABLE public.module_versions DROP CONSTRAINT IF EXISTS module_versions_published_by_fkey;
    ALTER TABLE public.module_versions ADD CONSTRAINT module_versions_published_by_fkey FOREIGN KEY (published_by) REFERENCES identity.users(id);

    ALTER TABLE public.modules DROP CONSTRAINT IF EXISTS modules_created_by_fkey;
    ALTER TABLE public.modules ADD CONSTRAINT modules_created_by_fkey FOREIGN KEY (created_by) REFERENCES identity.users(id);

    ALTER TABLE public.modules DROP CONSTRAINT IF EXISTS modules_organization_id_fkey;
    ALTER TABLE public.modules ADD CONSTRAINT modules_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id) ON DELETE CASCADE;

    ALTER TABLE public.provider_versions DROP CONSTRAINT IF EXISTS provider_versions_published_by_fkey;
    ALTER TABLE public.provider_versions ADD CONSTRAINT provider_versions_published_by_fkey FOREIGN KEY (published_by) REFERENCES identity.users(id);

    ALTER TABLE public.providers DROP CONSTRAINT IF EXISTS providers_created_by_fkey;
    ALTER TABLE public.providers ADD CONSTRAINT providers_created_by_fkey FOREIGN KEY (created_by) REFERENCES identity.users(id);

    ALTER TABLE public.providers DROP CONSTRAINT IF EXISTS providers_organization_id_fkey;
    ALTER TABLE public.providers ADD CONSTRAINT providers_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id) ON DELETE CASCADE;

    ALTER TABLE public.scm_oauth_tokens DROP CONSTRAINT IF EXISTS scm_oauth_tokens_user_id_fkey;
    ALTER TABLE public.scm_oauth_tokens ADD CONSTRAINT scm_oauth_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES identity.users(id) ON DELETE CASCADE;

    ALTER TABLE public.scm_providers DROP CONSTRAINT IF EXISTS scm_providers_organization_id_fkey;
    ALTER TABLE public.scm_providers ADD CONSTRAINT scm_providers_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id) ON DELETE CASCADE;

    ALTER TABLE public.storage_config DROP CONSTRAINT IF EXISTS storage_config_created_by_fkey;
    ALTER TABLE public.storage_config ADD CONSTRAINT storage_config_created_by_fkey FOREIGN KEY (created_by) REFERENCES identity.users(id);

    ALTER TABLE public.storage_config DROP CONSTRAINT IF EXISTS storage_config_updated_by_fkey;
    ALTER TABLE public.storage_config ADD CONSTRAINT storage_config_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES identity.users(id);

    ALTER TABLE public.storage_migrations DROP CONSTRAINT IF EXISTS storage_migrations_created_by_fkey;
    ALTER TABLE public.storage_migrations ADD CONSTRAINT storage_migrations_created_by_fkey FOREIGN KEY (created_by) REFERENCES identity.users(id);

    ALTER TABLE public.system_settings DROP CONSTRAINT IF EXISTS system_settings_storage_configured_by_fkey;
    ALTER TABLE public.system_settings ADD CONSTRAINT system_settings_storage_configured_by_fkey FOREIGN KEY (storage_configured_by) REFERENCES identity.users(id);

    ALTER TABLE public.version_approval_events DROP CONSTRAINT IF EXISTS version_approval_events_performed_by_fkey;
    ALTER TABLE public.version_approval_events ADD CONSTRAINT version_approval_events_performed_by_fkey FOREIGN KEY (performed_by) REFERENCES identity.users(id) ON DELETE SET NULL;

    ALTER TABLE public.version_immutability_violations DROP CONSTRAINT IF EXISTS version_immutability_violations_resolved_by_fkey;
    ALTER TABLE public.version_immutability_violations ADD CONSTRAINT version_immutability_violations_resolved_by_fkey FOREIGN KEY (resolved_by) REFERENCES identity.users(id);
  END IF;
END $$;
