ALTER TABLE mirror_configurations
    DROP COLUMN IF EXISTS pull_through_cache_ttl_hours,
    DROP COLUMN IF EXISTS pull_through_enabled;
