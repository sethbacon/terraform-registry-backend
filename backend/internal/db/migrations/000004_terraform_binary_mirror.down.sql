-- Reverse the Terraform binary mirror migration.

DROP TABLE IF EXISTS terraform_sync_history;
DROP TABLE IF EXISTS terraform_version_platforms;
DROP TABLE IF EXISTS terraform_versions;
DROP TABLE IF EXISTS terraform_mirror_configs;
