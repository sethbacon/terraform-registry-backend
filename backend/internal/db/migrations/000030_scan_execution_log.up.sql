ALTER TABLE module_version_scans
    ADD COLUMN IF NOT EXISTS execution_log TEXT;
