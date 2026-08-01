// Package credlifecycle centralises the invalidation of every credential
// family that carries a *snapshot* of a principal's derived authority.
//
// The registry issues two credential families whose authority is frozen at
// issue time rather than re-derived from the database on every request:
//
//   - JWT sessions — the scope list is embedded in the claims at login
//     (auth.GenerateJWT) and is never re-read; only a JTI denylist hit or the
//     per-user revoke-all watermark (UserTokenRevocationRepository) stops one.
//   - API keys — BOTH the scope list AND the owning organization_id are stored
//     on the api_keys row at creation and are copied straight into the request
//     context by middleware.AuthMiddleware ("scopes", "organization_id").
//     Nothing re-derives them from the owner's current membership or role
//     template.
//
// It follows that any event which REDUCES a principal's derived authority —
// removal from an organization, reassignment of their role template, an edit
// or deletion of the role template itself, or IdP-driven deprovisioning via
// SCIM or a group-mapping sync — must invalidate BOTH families, or the
// reduction is cosmetic for whichever family it forgot.
//
// Before issues #732 and #736 only the JWT family was swept, and only at some
// of those events: an offboarded member kept a working publish credential into
// the org's namespaces indefinitely, and SCIM deprovisioning swept nothing at
// all. This package exists so the sweep is one call with one meaning rather
// than a fragment re-derived at each call site.
//
// SHARED-MODULE NOTE: the truly authoritative home for this is the shared
// identity module (github.com/sethbacon/terraform-suite-identity), where both
// organization_members and api_keys are owned and where the removal and the
// sweep could be one transaction. This package is the consumer-side
// composition available without editing that module; it is best-effort (the
// authority change has already committed) rather than atomic.
package credlifecycle

import (
	"context"
	"log/slog"

	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// Sweeper invalidates the credential families derived from an authority that
// has just been reduced.
//
// A nil *Sweeper is a valid no-op receiver: handlers constructed without the
// revocation subsystem wired (most unit tests, and any deployment that has not
// provisioned the user_token_revocations table) keep their previous behaviour
// instead of panicking or issuing unexpected queries.
type Sweeper struct {
	// userRevocations moves the per-user JWT revoke-all watermark. Lives on the
	// registry's own connection.
	userRevocations *repositories.UserTokenRevocationRepository
	// apiKeys deletes API-key rows. Lives on the identity connection.
	apiKeys *repositories.APIKeyRepository
}

// NewSweeper builds a Sweeper. Either repository may be nil, in which case
// that family is simply not swept; if both are nil the constructor returns nil
// so callers can store the result directly and rely on the no-op receiver.
func NewSweeper(userRevocations *repositories.UserTokenRevocationRepository, apiKeys *repositories.APIKeyRepository) *Sweeper {
	if userRevocations == nil && apiKeys == nil {
		return nil
	}
	return &Sweeper{userRevocations: userRevocations, apiKeys: apiKeys}
}

// Outcome reports what a sweep actually managed to invalidate. Every sweep is
// best-effort: by the time it runs, the authority change has already been
// committed, so a failure is reported and logged rather than rolled back —
// turning it into an error response would falsely tell the caller that the
// (already applied) removal did not happen. Incomplete lets a handler surface
// "the reduction landed but the credential sweep did not" to its caller.
type Outcome struct {
	TokensRevoked bool
	KeysRevoked   int
	Incomplete    bool
}

// OrgAuthorityReduced invalidates the credentials a user derives from ONE
// organization: their JWT sessions (which carry a cross-org scope union that
// included this org) and every API key bound to that organization.
//
// Use for membership removal and for a membership's role-template change: in
// both cases the org-bound key's stored scopes are a snapshot of an authority
// the user no longer has, and middleware.AuthMiddleware will keep serving that
// snapshot until the row is gone.
func (s *Sweeper) OrgAuthorityReduced(ctx context.Context, userID, orgID, reason string) Outcome {
	if s == nil {
		return Outcome{}
	}
	out := s.revokeTokens(ctx, userID, reason)
	keys, incomplete := s.revokeOrgKeys(ctx, userID, orgID, reason)
	out.KeysRevoked = keys
	out.Incomplete = out.Incomplete || incomplete
	return out
}

// OrgKeysOnly invalidates only the API keys a user derives from ONE
// organization, deliberately leaving the JWT watermark untouched.
//
// This exists for the IdP login path (OIDC/SAML group-mapping reconciliation).
// That reconciliation runs a few hundred microseconds BEFORE the same request
// mints the user's new session JWT, and RevokeAllUserTokens writes a
// full-precision NOW() watermark while a JWT's iat is floored to the second
// (RFC 7519). Moving the watermark there would make the freshly minted token
// compare as revoked — TokensRevokedSince deliberately resolves that
// same-second ambiguity toward "revoked" — and the user could never log in.
// The fresh token is issued from GetUserCombinedScopes AFTER the membership was
// removed, so it already carries the reduced authority; the API keys are the
// family that would otherwise survive the deprovisioning indefinitely.
func (s *Sweeper) OrgKeysOnly(ctx context.Context, userID, orgID, reason string) Outcome {
	if s == nil {
		return Outcome{}
	}
	keys, incomplete := s.revokeOrgKeys(ctx, userID, orgID, reason)
	return Outcome{KeysRevoked: keys, Incomplete: incomplete}
}

// UserDeprovisioned invalidates every credential the user holds anywhere: JWT
// sessions plus every API key in every organization.
//
// Use for whole-principal offboarding — SCIM DELETE /Users/{id}, SCIM
// active=false via PUT or PATCH — where the user retains no authority at all.
func (s *Sweeper) UserDeprovisioned(ctx context.Context, userID, reason string) Outcome {
	if s == nil {
		return Outcome{}
	}
	out := s.revokeTokens(ctx, userID, reason)
	if s.apiKeys == nil {
		return out
	}
	keys, err := s.apiKeys.ListAPIKeysByUser(ctx, userID)
	if err != nil {
		slog.Error("credlifecycle: failed to list user API keys for revocation",
			"user_id", userID, "reason", reason, "error", err)
		out.Incomplete = true
		return out
	}
	for _, k := range keys {
		if err := s.apiKeys.RevokeAPIKey(ctx, k.ID); err != nil {
			slog.Error("credlifecycle: failed to revoke API key",
				"api_key_id", k.ID, "user_id", userID, "reason", reason, "error", err)
			out.Incomplete = true
			continue
		}
		out.KeysRevoked++
		slog.Info("credlifecycle: API key revoked", "api_key_id", k.ID, "user_id", userID, "reason", reason)
	}
	return out
}

func (s *Sweeper) revokeTokens(ctx context.Context, userID, reason string) Outcome {
	if s.userRevocations == nil {
		return Outcome{}
	}
	if err := s.userRevocations.RevokeAllUserTokens(ctx, userID); err != nil {
		slog.Error("credlifecycle: failed to revoke user tokens after authority reduction",
			"user_id", userID, "reason", reason, "error", err)
		return Outcome{Incomplete: true}
	}
	return Outcome{TokensRevoked: true}
}

// revokeOrgKeys deletes every API key owned by userID and bound to orgID.
// Deletion (rather than scope narrowing) matches the recommendation on #732
// and the existing posture for the JWT family, which is likewise invalidated
// wholesale rather than re-scoped.
func (s *Sweeper) revokeOrgKeys(ctx context.Context, userID, orgID, reason string) (int, bool) {
	if s.apiKeys == nil || orgID == "" {
		return 0, false
	}
	keys, err := s.apiKeys.ListByUserAndOrganization(ctx, userID, orgID)
	if err != nil {
		slog.Error("credlifecycle: failed to list org-bound API keys for revocation",
			"user_id", userID, "organization_id", orgID, "reason", reason, "error", err)
		return 0, true
	}
	revoked, incomplete := 0, false
	for _, k := range keys {
		if err := s.apiKeys.RevokeAPIKey(ctx, k.ID); err != nil {
			slog.Error("credlifecycle: failed to revoke org-bound API key",
				"api_key_id", k.ID, "user_id", userID, "organization_id", orgID, "reason", reason, "error", err)
			incomplete = true
			continue
		}
		revoked++
		slog.Info("credlifecycle: API key revoked",
			"api_key_id", k.ID, "user_id", userID, "organization_id", orgID, "reason", reason)
	}
	return revoked, incomplete
}
