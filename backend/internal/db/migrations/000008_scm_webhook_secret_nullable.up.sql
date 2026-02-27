-- Make webhook_secret nullable so SCM providers can be created without a webhook secret.
-- The column was originally NOT NULL but the field is optional in the API request struct
-- (omitempty), causing a 500 error when an empty string was submitted.
ALTER TABLE scm_providers
    ALTER COLUMN webhook_secret DROP NOT NULL,
    ALTER COLUMN webhook_secret SET DEFAULT '';
