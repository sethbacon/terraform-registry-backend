-- 000050_quarantine_orphaned_api_keys
--
-- Retire API keys that were ORPHANED by a user deletion before the credential
-- lifecycle sweep shipped (issues #732, #736).
--
-- WHY THESE ROWS EXIST
--
--   identity.api_keys.user_id UUID REFERENCES identity.users(id) ON DELETE SET NULL
--
-- Deleting a principal therefore DETACHED their API keys instead of destroying
-- them. The detached row keeps its organization_id and its frozen scopes, and
-- until this batch the namespace authorizer read a userless org-bound key as an
-- "organization service credential" and skipped the membership check entirely:
-- the deleted user's key kept publishing into the organization's namespaces.
--
-- The code fix closes the class going FORWARD (every user-deletion site now
-- sweeps the principal's keys before the row goes away) and fails closed at the
-- point of use. Neither helps rows that were already detached when the upgrade
-- ran. This migration drains that backward population.
--
-- WHY QUARANTINE RATHER THAN DELETE
--
-- Expiring the row retires the credential on EVERY code path -- both
-- AuthMiddleware and OptionalAuthMiddleware reject an expired key before any
-- handler runs -- while leaving the row visible to an operator. Deleting would
-- destroy the audit trail of a credential that was, by construction, live and
-- possibly in use.
--
-- WHY IT IS SAFE TO RETIRE ALL OF THEM
--
-- The registry mints an API key in exactly two places
-- (internal/api/admin/apikeys.go: CreateAPIKeyHandler sets UserID from the
-- authenticated caller, RotateAPIKeyHandler copies the old key's UserID), and
-- the identity store has exactly one INSERT. No supported path produces a key
-- with a NULL user_id. Every userless row is therefore either a detached
-- personal key or a hand-written INSERT -- not a credential this product
-- issues. An operator who deliberately created one by direct SQL can identify
-- the row and clear expires_at; see docs/upgrade-guide.md.
--
-- Idempotent: re-running matches nothing new. Rows that were already expired
-- are left alone so their original expiry is preserved.
--
-- NOTE: the identity half hardcodes the schema literal `identity`, like
-- migrations 000038 and 000045. Deployments that set TFR_IDENTITY_SCHEMA_NAME
-- to something else must edit this file, or run the statement by hand.
DO $$
DECLARE
  quarantined BIGINT;
BEGIN
  IF to_regclass('identity.api_keys') IS NOT NULL THEN
    UPDATE identity.api_keys
       SET expires_at = NOW(),
           updated_at = NOW()
     WHERE user_id IS NULL
       AND (expires_at IS NULL OR expires_at > NOW());
    GET DIAGNOSTICS quarantined = ROW_COUNT;
    IF quarantined > 0 THEN
      RAISE WARNING 'migration 000050: quarantined % orphaned identity.api_keys row(s) (user_id IS NULL). These were detached by a user deletion under ON DELETE SET NULL and were authorizing as organization service credentials.', quarantined;
    END IF;
  END IF;

  -- public.api_keys declares user_id ON DELETE CASCADE, so a deletion cannot
  -- orphan a key here. Run it anyway: the column is nullable, and a nonzero
  -- count is itself the finding. Guarded on the table existing so this cannot
  -- become a migration that fails startup on a deployment that dropped it.
  IF to_regclass('public.api_keys') IS NOT NULL THEN
    UPDATE public.api_keys
       SET expires_at = NOW()
     WHERE user_id IS NULL
       AND (expires_at IS NULL OR expires_at > NOW());
    GET DIAGNOSTICS quarantined = ROW_COUNT;
    IF quarantined > 0 THEN
      RAISE WARNING 'migration 000050: quarantined % userless public.api_keys row(s).', quarantined;
    END IF;
  END IF;
END $$;
