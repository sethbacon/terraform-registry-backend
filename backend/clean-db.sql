-- Clean database for re-upload with README support
-- This will delete all modules and providers (versions cascade delete)

DELETE FROM module_versions;
DELETE FROM modules;
DELETE FROM provider_platforms;
DELETE FROM provider_versions;
DELETE FROM providers;

-- Show confirmation
SELECT 'Database cleaned successfully. All modules and providers deleted.' as status;
