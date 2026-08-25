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

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
)

// AuthorityRetained reports whether every scope in have is still granted by
// retained -- i.e. whether a credential frozen with `have` still asks for no
// more than the principal currently holds.
//
// This is the whole difference between "the authority changed" and "the
// authority was REDUCED", and the sweep must key off the latter. Deleting API
// keys is irreversible (a key's secret is shown exactly once and is not
// recoverable), so a sweep triggered by an authority INCREASE, or by a mere
// reordering of an unchanged scope list, destroys working credentials
// fleet-wide for no security benefit.
//
// Comparison is by scope semantics, not by slice identity: auth.HasScope
// resolves the "admin" wildcard and the read/write implications, so
// ["modules:read"] is retained under ["modules:write"], and everything is
// retained under ["admin"]. An empty `retained` grants nothing, so any
// credential carrying at least one scope is not retained; a credential with no
// scopes grants nothing and is vacuously retained.
func AuthorityRetained(have, retained []string) bool {
	for _, s := range have {
		if !auth.HasScope(retained, auth.Scope(s)) {
			return false
		}
	}
	return true
}

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
	// audit records what was destroyed. Optional: nil means no audit rows are
	// written and behaviour is byte-identical to before #961, which is what
	// keeps every existing construction and its tests valid.
	audit *repositories.AuditRepository
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

// WithAuditLog attaches the audit repository that records each destroyed key.
// Chainable and nil-safe on both sides so a construction that has no audit
// repository -- or no Sweeper at all -- keeps working unchanged.
//
// This is deliberately NOT a NewSweeper parameter: every existing call site
// would have to be edited, and the ones that were missed would be silently
// un-audited rather than failing to compile. Making it an explicit opt-in keeps
// the wiring greppable.
func (s *Sweeper) WithAuditLog(audit *repositories.AuditRepository) *Sweeper {
	if s == nil {
		return nil
	}
	s.audit = audit
	return s
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
	// KeysRetained counts keys the sweep deliberately left alone because every
	// scope they carry is still granted by the principal's remaining authority.
	KeysRetained int
	Incomplete   bool
	// AuditIncomplete reports that the sweep destroyed credentials it could not
	// fully record. Kept SEPARATE from Incomplete on purpose: callers such as
	// users.go and user_service.go treat Incomplete as "the enclosing
	// destructive operation did not fully land" and surface it to the client,
	// whereas a missing audit row means the destruction DID land and the trail
	// is short. Folding the two together would either hide a real sweep failure
	// or make a logging problem look like a failed deletion.
	AuditIncomplete bool
}

// OrgAuthorityReduced invalidates the credentials a user derives from ONE
// organization: their JWT sessions (which carry a cross-org scope union that
// included this org) and every API key bound to that organization.
//
// Use for membership removal and for a membership's role-template change: in
// both cases the org-bound key's stored scopes may be a snapshot of an
// authority the user no longer has, and middleware.AuthMiddleware will keep
// serving that snapshot until the row is gone.
//
// retained is the scope set the principal STILL holds in orgID after the
// change -- the new role template's scopes for a reassignment, nil for a
// removal. Only keys asking for more than that are deleted; see
// AuthorityRetained.
func (s *Sweeper) OrgAuthorityReduced(ctx context.Context, userID, orgID string, retained []string, reason string) Outcome {
	if s == nil {
		return Outcome{}
	}
	out := s.revokeTokens(ctx, userID, reason)
	keyOut := s.revokeOrgKeys(ctx, userID, orgID, retained, reason)
	out.KeysRevoked = keyOut.KeysRevoked
	out.KeysRetained = keyOut.KeysRetained
	out.Incomplete = out.Incomplete || keyOut.Incomplete
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
//
// EXACTLY WHAT THE EXEMPTION COVERS, AND WHAT IT DOES NOT.
//
// Covered: the token minted by THIS request. It is issued from
// GetUserCombinedScopes AFTER the membership change committed, so it already
// carries the reduced authority — moving the watermark would buy nothing and
// would break login.
//
// NOT covered — the residual: the user's OTHER live sessions, minted at
// EARLIER logins. Those carry the pre-reduction scope union and nothing here
// retires them; they stay valid until their own TTL expires. The same-second
// race justifies leaving the watermark alone for this request's token only,
// and it is a strictly narrower claim than "no JWT needs revoking here".
//
// The residual is accepted because the alternative is a login that can never
// succeed, and because the exposure is bounded by the JWT TTL, whereas the
// API-key family — the one this call does sweep — would otherwise survive the
// deprovisioning indefinitely. An operator who needs an IdP-driven reduction to
// retire every existing session immediately must take the administrative path
// (RemoveMemberHandler / UpdateMemberHandler / the role-template endpoints),
// which calls OrgAuthorityReduced and does move the watermark.
func (s *Sweeper) OrgKeysOnly(ctx context.Context, userID, orgID string, retained []string, reason string) Outcome {
	if s == nil {
		return Outcome{}
	}
	return s.revokeOrgKeys(ctx, userID, orgID, retained, reason)
}

// UserDeprovisioned invalidates every credential the user holds inside scope:
// JWT sessions plus every API key bound to an organization the scope admits.
//
// Use for whole-principal offboarding — SCIM DELETE /Users/{id}, SCIM
// active=false via PUT or PATCH, administrative deletion, GDPR erasure — where
// the user retains no authority in the organizations named by scope.
//
// scope is REQUIRED and its zero value sweeps nothing, so a caller that has not
// decided whose tenancy this is destroys no credentials. Pass the organizations
// whose membership was ACTUALLY just removed (OrganizationRepository
// .RemoveAllMembershipsForUser returns exactly that, as an OrgScope) so the
// sweep matches the authority reduction that triggered it: an organization
// where nothing was removed had no authority reduced and must keep its keys
// (identity #160), while every organization where authority WAS reduced is in
// the scope by construction, so nothing is stranded (#732/#736). Pass
// repositories.OrgScopeAllOrganizations() where the principal itself is being
// destroyed and no key may survive it.
//
// The JWT watermark is per-user and cannot be scoped: a session token carries
// the cross-organization scope union, so any reduction anywhere invalidates it.
func (s *Sweeper) UserDeprovisioned(ctx context.Context, userID string, scope repositories.OrgScope, reason string) Outcome {
	if s == nil {
		return Outcome{}
	}
	out := s.revokeTokens(ctx, userID, reason)
	if s.apiKeys == nil {
		return out
	}
	// One scoped DELETE rather than a list-then-revoke-each loop. The loop had
	// to special-case a key that vanished between the two statements — a benign
	// race that must not read as an incomplete sweep — and that whole branch is
	// gone with the second round trip: a set-based delete reports how many rows
	// it removed, and removing zero is an ordinary answer, not a miss.
	// Snapshot BEFORE the delete. The set-based DELETE reports only a count, and
	// once it runs the names and scopes exist nowhere -- so the pre-image is the
	// only chance to record what was destroyed. Read only when an audit sink is
	// attached, so an un-audited deployment issues no extra query.
	var snapshot []*models.APIKey
	if s.audit != nil {
		var listErr error
		snapshot, listErr = s.apiKeys.ListAPIKeysByUser(ctx, userID, scope)
		if listErr != nil {
			// Do NOT abort. The authority reduction has already committed, and
			// refusing to delete here would strand exactly the credentials this
			// sweep exists to remove (#732/#736). Proceed and report the gap.
			slog.Error("credlifecycle: could not snapshot API keys before revoking them",
				"user_id", userID, "reason", reason, "error", listErr,
				"impact", "the keys are still deleted below, but the audit trail will not name them")
			out.AuditIncomplete = true
			snapshot = nil
		}
	}
	n, err := s.apiKeys.RevokeAPIKeysForUser(ctx, userID, scope)
	if err != nil {
		slog.Error("credlifecycle: failed to revoke user API keys",
			"user_id", userID, "reason", reason, "error", err)
		out.Incomplete = true
		return out
	}
	out.KeysRevoked = int(n)
	slog.Info("credlifecycle: API keys revoked", "user_id", userID,
		"api_keys_revoked", n, "scope", scope.String(), "reason", reason)
	for _, k := range snapshot {
		if !s.recordKeyDestroyed(ctx, k, reason) {
			out.AuditIncomplete = true
		}
	}
	// A snapshot that disagrees with the delete count means rows arrived or
	// vanished between the two statements, so the trail is not a faithful
	// account of what this sweep destroyed. Say so rather than letting the
	// mismatch pass silently.
	if s.audit != nil && len(snapshot) != int(n) {
		slog.Warn("credlifecycle: audit snapshot does not match the number of keys deleted",
			"user_id", userID, "snapshotted", len(snapshot), "deleted", n, "reason", reason)
		out.AuditIncomplete = true
	}
	return out
}

// SweepActor is the actor_email recorded for a sweep-initiated destruction.
//
// These writes have no HTTP actor reachable from here. Four of the five call
// sites DO run inside an authenticated request, but the Sweeper receives only a
// context and never the caller's identity, so attributing the row to a person
// would require threading a principal through every path -- and guessing wrong
// is worse than being explicit that the system did it. audit_logs.actor_email
// (migration 000058) is NOT NULL-safe but a null actor is unreadable in the
// admin surface, so a sentinel is used instead.
const SweepActor = "system:credlifecycle"

// recordKeyDestroyed writes the audit row for one destroyed key. It reports
// whether the record was written.
//
// The row must make the destruction RECONSTRUCTABLE: the api_keys row is
// hard-deleted (identity models revocation as deletion and deliberately dropped
// is_active in its migration 000004), so name, scopes and prefix exist nowhere
// else once this returns. Scopes matter most -- they are what tells the owner
// what the key could do and therefore what to recreate.
func (s *Sweeper) recordKeyDestroyed(ctx context.Context, k *models.APIKey, reason string) bool {
	if s == nil || s.audit == nil || k == nil {
		return true
	}
	resourceType := "api_key"
	resourceID := k.ID
	orgID := k.OrganizationID
	actor := SweepActor

	metadata := map[string]interface{}{
		"name":       k.Name,
		"scopes":     k.Scopes,
		"key_prefix": k.KeyPrefix,
		"reason":     reason,
		"created_at": k.CreatedAt,
	}
	if k.UserID != nil {
		metadata["owner_user_id"] = *k.UserID
	}
	if k.Description != nil {
		metadata["description"] = *k.Description
	}
	if k.ExpiresAt != nil {
		metadata["expires_at"] = *k.ExpiresAt
	}
	if k.LastUsedAt != nil {
		metadata["last_used_at"] = *k.LastUsedAt
	}

	entry := &models.AuditLog{
		// UserID stays nil: the row records a SYSTEM action, and the audit
		// repository resolves actor_email from user_id when ActorEmail is unset.
		OrganizationID: &orgID,
		Action:         "api_key.revoked_by_sweep",
		ResourceType:   &resourceType,
		ResourceID:     &resourceID,
		Metadata:       metadata,
		ActorEmail:     &actor,
	}
	if err := s.audit.CreateAuditLog(ctx, entry); err != nil {
		slog.Error("credlifecycle: destroyed an API key but could not record it in the audit log",
			"api_key_id", k.ID, "organization_id", k.OrganizationID, "reason", reason, "error", err,
			"impact", "the key is gone and its name and scopes are not recoverable from the audit trail")
		return false
	}
	return true
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

// revokeOrgKeys deletes the API keys owned by userID and bound to orgID whose
// frozen scopes are no longer covered by `retained`.
//
// Deletion (rather than scope narrowing) is the mechanism, matching the
// recommendation on #732 and the posture for the JWT family, which is likewise
// invalidated wholesale rather than re-scoped. But the mechanism is
// irreversible -- an API key's secret is displayed once at creation and cannot
// be recovered -- so it is applied per key and only where the key actually
// over-asks. Without that filter, an authority INCREASE or a cosmetic
// reordering of a role template's scope list would hard-delete every affected
// member's keys fleet-wide.
func (s *Sweeper) revokeOrgKeys(ctx context.Context, userID, orgID string, retained []string, reason string) Outcome {
	if s.apiKeys == nil || orgID == "" {
		return Outcome{}
	}
	// The organization is named by the caller and was authorized by the route
	// guard that reached this sweep, so it is also the tenancy: this accessor is
	// asked about that one organization and no other, and a key belonging to any
	// other tenant cannot come back to be considered for deletion.
	orgScope := repositories.OrgScopeOrganizations(orgID)
	keys, err := s.apiKeys.ListByUserAndOrganization(ctx, userID, orgID, orgScope)
	if err != nil {
		slog.Error("credlifecycle: failed to list org-bound API keys for revocation",
			"user_id", userID, "organization_id", orgID, "reason", reason, "error", err)
		return Outcome{Incomplete: true}
	}
	var out Outcome
	for _, k := range keys {
		if AuthorityRetained(k.Scopes, retained) {
			out.KeysRetained++
			continue
		}
		if err := s.apiKeys.RevokeAPIKey(ctx, k.ID, orgScope); err != nil {
			// Same race, same reasoning as UserDeprovisioned's former loop:
			// already gone is the desired end state, not an incomplete sweep.
			// This one keeps the per-key shape because AuthorityRetained decides
			// per key whether the credential over-asks at all, which no single
			// DELETE can express.
			if identityerr.IsNotFound(err) {
				slog.Info("credlifecycle: org-bound API key already gone before revocation",
					"api_key_id", k.ID, "user_id", userID, "organization_id", orgID, "reason", reason)
				continue
			}
			slog.Error("credlifecycle: failed to revoke org-bound API key",
				"api_key_id", k.ID, "user_id", userID, "organization_id", orgID, "reason", reason, "error", err)
			out.Incomplete = true
			continue
		}
		out.KeysRevoked++
		slog.Info("credlifecycle: API key revoked",
			"api_key_id", k.ID, "user_id", userID, "organization_id", orgID, "reason", reason)
		// Recorded AFTER the delete, deliberately. Auditing first would
		// manufacture a record of a destruction that might then not happen, and
		// a phantom entry corrupts the trail in a way a missing one does not --
		// a miss is loud in the error log and sets AuditIncomplete.
		if !s.recordKeyDestroyed(ctx, k, reason) {
			out.AuditIncomplete = true
		}
	}
	return out
}
