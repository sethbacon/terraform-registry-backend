-- Reversible. A federated provider becomes an entra_app provider with no client
-- secret, which the pre-#1037 API rejects on the next update -- correctly, since
-- without this column there is no way to express what it was.
ALTER TABLE scm_providers DROP CONSTRAINT IF EXISTS scm_providers_entra_credential_shape;
ALTER TABLE scm_providers DROP COLUMN IF EXISTS entra_credential_type;
