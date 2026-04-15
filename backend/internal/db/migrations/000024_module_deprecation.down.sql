DROP INDEX IF EXISTS idx_modules_deprecated;
ALTER TABLE modules DROP COLUMN IF EXISTS successor_module_id;
ALTER TABLE modules DROP COLUMN IF EXISTS deprecation_message;
ALTER TABLE modules DROP COLUMN IF EXISTS deprecated_at;
ALTER TABLE modules DROP COLUMN IF EXISTS deprecated;
