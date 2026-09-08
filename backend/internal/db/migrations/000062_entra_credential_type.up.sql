-- Numbered 000062 because 000061 is the NULL-organization backfill (#1035),
-- which is in flight on its own branch. If that lands after this one, renumber
-- rather than merging: golang-migrate orders by the number, and two migrations
-- sharing one is a dirty-state failure on first boot.
--
-- entra_credential_type selects HOW an entra_app provider proves itself, so the
-- credential is no longer implicitly "a client secret" (issue #1037).
--
-- Microsoft's guidance is that client secrets should not be used in production,
-- and Entra caps their lifetime at 24 months (recommending under 12), so every
-- deployment on a secret inherits a hard expiry and a rotation outage risk.
-- 'federated' is workload identity federation: the platform projects a token,
-- that token is exchanged for an Entra one, and no secret is stored anywhere.
--
-- DEFAULTS TO 'client_secret' so every existing row keeps its current behaviour
-- without being touched. The column is only meaningful when auth_mode =
-- 'entra_app'; rows in other modes carry the default and ignore it.
--
-- 'managed_identity' and 'certificate' are deliberately NOT in the CHECK yet.
-- They are tracked separately (#1042, #1041) and each needs a decision this
-- migration should not pre-empt: a managed identity introduces an IMDS failure
-- mode that only exists on Azure compute, and a certificate trades a capped
-- secret for a private key with no rotation story. Adding a value to a CHECK
-- later is a one-line migration; removing one that turned out to be wrong is not.
ALTER TABLE scm_providers
    ADD COLUMN entra_credential_type TEXT NOT NULL DEFAULT 'client_secret'
        CHECK (entra_credential_type IN ('client_secret', 'federated'));

-- Shape guard, mirroring scm_providers_app_shape for github_app: an entra_app
-- provider using a client secret must actually carry one. A federated provider
-- must NOT -- storing an unused secret beside a credential type that ignores it
-- is how a rotated-away secret survives in the database and is later mistaken
-- for the live credential.
--
-- Scoped to auth_mode='entra_app' so oauth_user rows, which legitimately hold a
-- client secret for the user-authorization flow, are unaffected.
ALTER TABLE scm_providers
    ADD CONSTRAINT scm_providers_entra_credential_shape CHECK (
        auth_mode <> 'entra_app'
        OR (entra_credential_type = 'client_secret' AND client_secret_encrypted IS NOT NULL
                AND client_secret_encrypted <> '')
        OR (entra_credential_type = 'federated' AND (client_secret_encrypted IS NULL
                OR client_secret_encrypted = ''))
    );
