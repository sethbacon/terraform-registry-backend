-- Drop triggers
DROP TRIGGER IF EXISTS trg_providers_search_vector ON providers;
DROP TRIGGER IF EXISTS trg_modules_search_vector ON modules;

-- Drop trigger functions
DROP FUNCTION IF EXISTS providers_search_vector_update();
DROP FUNCTION IF EXISTS modules_search_vector_update();

-- Drop GIN indexes
DROP INDEX IF EXISTS idx_providers_search;
DROP INDEX IF EXISTS idx_modules_search;

-- Drop tsvector columns
ALTER TABLE providers DROP COLUMN IF EXISTS search_vector;
ALTER TABLE modules DROP COLUMN IF EXISTS search_vector;
