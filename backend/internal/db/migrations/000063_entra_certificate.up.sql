-- A third way for an entra_app provider to prove itself: a CERTIFICATE. The
-- app signs a client assertion with a private key it holds, and no secret ever
-- crosses the wire (issue #1041). The mechanism lives in
-- terraform-suite-identity/identity/appcreds; this is the storage for it.
--
-- WHERE THE KEY LIVES. Encrypted in this column, sealed with the token cipher
-- and bound to the provider row -- exactly as the GitHub App private key has
-- been stored in encrypted_app_private_key since it shipped. #1041 asked
-- whether a certificate is a win when the key sits in the same kind of column
-- the client secret does. It is, twice over: a client secret is SENT on every
-- token request while this key only ever signs locally, and a secret's
-- lifetime is Entra's (capped at 24 months) while a certificate's is the
-- operator's. A file-mount or key-vault key SOURCE can layer on later without
-- changing the credential type this column records.
--
-- The column holds the whole PEM bundle -- certificate (or chain) plus the
-- unencrypted private key -- as one value, because the two are only meaningful
-- together: Entra matches the assertion by the certificate's thumbprint, so a
-- key without its certificate cannot name itself and a certificate without its
-- key cannot sign.
ALTER TABLE scm_providers ADD COLUMN encrypted_entra_certificate TEXT;

-- Widen the credential-type CHECK from two values to three. The constraint was
-- created inline by 000062, so its name is whatever PostgreSQL generated;
-- resolve it from the catalog rather than hard-coding a guess that would make
-- this migration fail on a database where the auto-name differs.
--
-- Matched on the ANY form, not IN: PostgreSQL normalises `IN ('a', 'b')` to
-- `= ANY (ARRAY['a', 'b'])` when it stores the definition, so a LIKE on "IN"
-- finds nothing and the RAISE below fires on every database. Found the first
-- time this ran against a real one. The IN form is kept as an alternative for
-- a hand-restored schema that never went through the normaliser.
DO $$
DECLARE
    con_name text;
BEGIN
    SELECT conname INTO con_name
      FROM pg_constraint
     WHERE conrelid = 'scm_providers'::regclass
       AND contype = 'c'
       AND conname <> 'scm_providers_entra_credential_shape'
       AND (pg_get_constraintdef(oid) LIKE '%entra_credential_type = ANY%'
            OR pg_get_constraintdef(oid) LIKE '%entra_credential_type IN%');
    IF con_name IS NULL THEN
        RAISE EXCEPTION 'migration 000063: could not find the entra_credential_type CHECK from 000062';
    END IF;
    EXECUTE format('ALTER TABLE scm_providers DROP CONSTRAINT %I', con_name);
END $$;

ALTER TABLE scm_providers
    ADD CONSTRAINT scm_providers_entra_credential_type_check
        CHECK (entra_credential_type IN ('client_secret', 'federated', 'certificate'));

-- The shape guard from 000062, extended for the third type. Each type carries
-- EXACTLY its own material and nothing of the others': a certificate provider
-- with a leftover secret, or a client_secret provider with a leftover
-- certificate, is how a retired credential survives in the database and is
-- later mistaken for the live one. managed_identity (#1042) is still absent on
-- purpose.
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
