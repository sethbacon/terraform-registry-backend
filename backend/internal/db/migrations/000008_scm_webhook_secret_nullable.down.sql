-- Revert: restore webhook_secret as NOT NULL (empty string default preserved for existing rows).
UPDATE scm_providers SET webhook_secret = '' WHERE webhook_secret IS NULL;

ALTER TABLE scm_providers
    ALTER COLUMN webhook_secret SET NOT NULL,
    ALTER COLUMN webhook_secret DROP DEFAULT;
