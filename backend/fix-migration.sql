-- Fix dirty migration state
UPDATE schema_migrations SET dirty = false WHERE version = 9;

-- Check current state
SELECT * FROM schema_migrations;
