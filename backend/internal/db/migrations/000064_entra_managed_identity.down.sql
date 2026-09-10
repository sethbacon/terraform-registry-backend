-- Refuses while any provider uses a managed identity: under the three-value
-- schema such a row could not mint and would fail the restored shape CHECK, so
-- the operator re-credentials first rather than being silently stranded. Same
-- posture as 000061's collision abort and 000063's certificate guard.
DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM scm_providers WHERE entra_credential_type = 'managed_identity';
    IF n > 0 THEN
        RAISE EXCEPTION 'migration 000064 down: % provider(s) use a managed identity credential; switch them to another credential type before reverting', n;
    END IF;
END $$;

ALTER TABLE scm_providers DROP CONSTRAINT scm_providers_entra_credential_shape;
ALTER TABLE scm_providers
    ADD CONSTRAINT scm_providers_entra_credential_shape CHECK (
        auth_mode <> 'entra_app'
        OR (entra_credential_type = 'client_secret'
                AND client_secret_encrypted IS NOT NULL AND client_secret_encrypted <> ''
                AND (encrypted_entra_certificate IS NULL OR encrypted_entra_certificate = ''))
        OR (entra_credential_type = 'federated'
                AND (client_secret_encrypted IS NULL OR client_secret_encrypted = '')
                AND (encrypted_entra_certificate IS NULL OR encrypted_entra_certificate = ''))
        OR (entra_credential_type = 'certificate'
                AND encrypted_entra_certificate IS NOT NULL AND encrypted_entra_certificate <> ''
                AND (client_secret_encrypted IS NULL OR client_secret_encrypted = ''))
    );

ALTER TABLE scm_providers DROP CONSTRAINT IF EXISTS scm_providers_entra_credential_type_check;
ALTER TABLE scm_providers
    ADD CONSTRAINT scm_providers_entra_credential_type_check
        CHECK (entra_credential_type IN ('client_secret', 'federated', 'certificate'));
