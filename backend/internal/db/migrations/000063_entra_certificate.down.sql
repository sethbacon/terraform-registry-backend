-- Reversible only when no provider is using a certificate. A certificate row
-- has no secret and no federation, so under the two-value schema it would be
-- an entra_app provider with no way to mint at all, and 000062's shape CHECK
-- would refuse it anyway. Fail closed and let the operator re-credential those
-- providers first, rather than silently stranding them (same posture as
-- 000061's collision abort).
DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM scm_providers WHERE entra_credential_type = 'certificate';
    IF n > 0 THEN
        RAISE EXCEPTION 'migration 000063 down: % provider(s) use a certificate credential; switch them to client_secret or federated before reverting', n;
    END IF;
END $$;

ALTER TABLE scm_providers DROP CONSTRAINT scm_providers_entra_credential_shape;
ALTER TABLE scm_providers
    ADD CONSTRAINT scm_providers_entra_credential_shape CHECK (
        auth_mode <> 'entra_app'
        OR (entra_credential_type = 'client_secret' AND client_secret_encrypted IS NOT NULL
                AND client_secret_encrypted <> '')
        OR (entra_credential_type = 'federated' AND (client_secret_encrypted IS NULL
                OR client_secret_encrypted = ''))
    );

ALTER TABLE scm_providers DROP CONSTRAINT IF EXISTS scm_providers_entra_credential_type_check;
ALTER TABLE scm_providers
    ADD CONSTRAINT scm_providers_entra_credential_type_check
        CHECK (entra_credential_type IN ('client_secret', 'federated'));

-- IF EXISTS on both, so a down after a partially-applied up (which golang-migrate
-- leaves dirty) can still bring the schema back rather than failing on the
-- thing the up never got to create.
ALTER TABLE scm_providers DROP COLUMN IF EXISTS encrypted_entra_certificate;
