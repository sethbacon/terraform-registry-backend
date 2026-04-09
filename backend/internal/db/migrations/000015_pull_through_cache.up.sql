ALTER TABLE mirror_configurations
    ADD COLUMN IF NOT EXISTS pull_through_enabled        BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS pull_through_cache_ttl_hours INTEGER  NOT NULL DEFAULT 24;

COMMENT ON COLUMN mirror_configurations.pull_through_enabled IS
    'If true, mirror endpoints fetch from upstream on cache miss instead of returning 404';
COMMENT ON COLUMN mirror_configurations.pull_through_cache_ttl_hours IS
    'Hours before re-fetching upstream metadata for a pull-through cached provider';
