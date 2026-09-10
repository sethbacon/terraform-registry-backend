-- A fourth way for an entra_app provider to prove itself: a user-assigned
-- MANAGED IDENTITY (issue #1042). The hosting platform holds the credential
-- entirely and the process asks its local identity endpoint for a token, so
-- there is no secret and no certificate anywhere -- not in this table, not in
-- the environment, not in transit to Entra.
--
-- NO NEW COLUMN. A managed-identity provider carries exactly what a federated
-- one carries: client_id and nothing else. The identity is selected by that id
-- and everything else comes from the platform. This is the whole storage
-- change: one more value in the type CHECK, and one more arm in the shape
-- CHECK that holds it to carrying no secret and no certificate.
--
-- WHETHER IT CAN MINT IS NOT A SCHEMA QUESTION. Managed identity only works on
-- Azure compute; off Azure there is no identity endpoint to answer. That is a
-- deployment fact, not a row fact, so it is declared by the operator in
-- TFR_SCM_ENTRA_CREDENTIAL_TYPES and enforced in the handler -- see
-- internal/config and internal/api/admin/scm_providers.go. The database's job
-- here is only to keep the row's SHAPE honest.
DO $$
DECLARE
    con_name text;
BEGIN
    -- Resolve by catalog rather than by an assumed name, and match the ANY
    -- form: PostgreSQL normalises `IN ('a','b')` to `= ANY (ARRAY['a','b'])`
    -- when it stores a constraint definition, so a LIKE on "IN" finds nothing.
    -- 000063 learned this the hard way against a real database.
    SELECT conname INTO con_name
      FROM pg_constraint
     WHERE conrelid = 'scm_providers'::regclass
       AND contype = 'c'
       AND conname <> 'scm_providers_entra_credential_shape'
       AND (pg_get_constraintdef(oid) LIKE '%entra_credential_type = ANY%'
            OR pg_get_constraintdef(oid) LIKE '%entra_credential_type IN%');
    IF con_name IS NULL THEN
        RAISE EXCEPTION 'migration 000064: could not find the entra_credential_type CHECK';
    END IF;
    EXECUTE format('ALTER TABLE scm_providers DROP CONSTRAINT %I', con_name);
END $$;

ALTER TABLE scm_providers
    ADD CONSTRAINT scm_providers_entra_credential_type_check
        CHECK (entra_credential_type IN
            ('client_secret', 'federated', 'certificate', 'managed_identity'));

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
        OR (entra_credential_type = 'managed_identity'
                AND (client_secret_encrypted IS NULL OR client_secret_encrypted = '')
                AND (encrypted_entra_certificate IS NULL OR encrypted_entra_certificate = ''))
    );
