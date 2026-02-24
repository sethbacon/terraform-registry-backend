ALTER TABLE terraform_version_platforms
    ADD COLUMN download_count BIGINT NOT NULL DEFAULT 0;
