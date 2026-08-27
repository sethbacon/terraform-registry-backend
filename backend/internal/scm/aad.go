package scm

import "github.com/google/uuid"

// Additional-authenticated-data contexts for the SCM secrets held at rest.
//
// Each binds a ciphertext to the row and column it belongs to, so a sealed value
// cannot be lifted out of one row and written into another by anyone with
// database write access. Without a context, GCM authenticates that move happily,
// because nothing in the ciphertext says where it belongs (suite-identity #153).
//
// They live in one file, and callers use them rather than building the string,
// because the seal and the open are in different files — and for some columns
// different packages. Two hand-built strings drift apart silently, and the
// failure surfaces as "cannot decrypt credential" long after the change that
// caused it.
//
// The identity in a context must be the identity of the ROW. Several encrypted
// columns in this service share a field NAME across different tables:
// AccessTokenEncrypted exists both on the shared per-provider app-token cache
// (keyed by provider) and on the per-user OAuth token (keyed by user+provider).
// Using one row family's context for another's ciphertext is not a mistake the
// compiler catches, so each function below names its table explicitly.

// ProviderTokenContext binds a cached shared app token to its provider row in
// scm_provider_tokens.
//
// This column is a CACHE: entries carry an expiry and are re-minted from the
// identity provider when stale. That is why it is the first column converted —
// a failure here degrades to minting a fresh token, not to losing a credential
// that only an operator could restore by hand.
//
// It is also why this column needs no backfill. Unbound entries are read through
// the transition path until they expire, and every re-mint writes the bound
// form, so the table converts itself. The irreplaceable columns do not have that
// property and will each need a sweep.
func ProviderTokenContext(scmProviderID uuid.UUID) []byte {
	return []byte("scm_provider_tokens:" + scmProviderID.String() + ":access_token")
}

// UserTokenContext binds a user's OAuth access token to its row in
// scm_user_tokens.
//
// DO NOT "FIX" THE TABLE NAME IN THESE LITERALS. There is no scm_user_tokens
// table and there never has been -- the rows live in scm_oauth_tokens. The
// string is not a reference to a table, it is an opaque domain separator that is
// already baked into every ciphertext in production. Changing it to the real
// table name changes the AAD, and every existing token then fails to open: not
// at deploy time where it would be noticed, but the next time each individual
// user's SCM link is used. Every affected user must re-link. The misleading name
// is cheaper than the migration to correct it.
//
// The row is keyed by BOTH the user and the provider, so both are in the
// context: binding to one axis alone would let a token be replayed across the
// other. Every SCMUserTokenRecord carries both fields, so read sites derive this
// from the record they are already holding rather than from surrounding scope —
// which is what keeps eleven call sites uniform and hard to get wrong.
//
// Distinct from ProviderTokenContext even though both columns are named
// AccessTokenEncrypted. Those are different tables with different keys, and the
// compiler cannot tell them apart.
func UserTokenContext(userID, scmProviderID uuid.UUID) []byte {
	return []byte("scm_user_tokens:" + userID.String() + ":" + scmProviderID.String() + ":access_token")
}

// ProviderClientSecretContext binds a provider's OAuth client secret to its row
// in scm_providers.
//
// Note the table: ProviderTokenContext above is keyed by the SAME provider id
// but names scm_provider_tokens, so the two cannot be confused even though both
// contexts contain the same uuid. The table prefix is doing real work here, not
// decoration.
//
// This one takes the id as TEXT, unlike the three above. It is a column the
// bind-secrets sweep converts, and the sweep reads row ids as text out of the
// database; giving it a uuid.UUID form would mean either a second function or a
// parse with nowhere to report failure, and two derivations of one context
// string is exactly the drift that ends with a credential that no longer
// decrypts. Callers pass provider.ID.String().
func ProviderClientSecretContext(scmProviderID string) []byte {
	return []byte("scm_providers:" + scmProviderID + ":client_secret_encrypted")
}

// ProviderAppPrivateKeyContext binds a GitHub App private key to its provider
// row in scm_providers.
//
// Distinct from ProviderClientSecretContext for the SAME row, for the same
// reason the access and refresh tokens are distinct: both columns live side by
// side, and a row-level context alone would let the App private key — which
// authenticates as the installation itself — be written into the client-secret
// column of its own row and still decrypt there.
func ProviderAppPrivateKeyContext(scmProviderID string) []byte {
	return []byte("scm_providers:" + scmProviderID + ":encrypted_app_private_key")
}

// UserRefreshTokenContext binds a user's OAuth refresh token to its row.
//
// Deliberately distinct from UserTokenContext for the SAME row. Without that, an
// access token could be written into the refresh column of its own row, or the
// reverse, and still authenticate — a move WITHIN one row that a row-level
// context alone does not catch, and one that hands a long-lived credential to a
// path expecting a short-lived one.
func UserRefreshTokenContext(userID, scmProviderID uuid.UUID) []byte {
	return []byte("scm_user_tokens:" + userID.String() + ":" + scmProviderID.String() + ":refresh_token")
}
