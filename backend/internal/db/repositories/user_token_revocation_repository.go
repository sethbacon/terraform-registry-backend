// user_token_revocation_repository.go implements per-user token-revocation
// watermarks (issue #559 finding [9]).
//
// The JTI denylist (TokenRepository / revoked_tokens) can only revoke tokens
// whose JTI is known — logout and admin single-token revocation. Privilege
// changes (a member's role template is changed, a member is removed from an
// organization, a role template's scopes are edited) must instead invalidate
// every outstanding token for the affected user. Since issued JTIs are not
// tracked, this repository stores a per-user watermark: any JWT whose iat
// predates the watermark is treated as revoked by the auth middleware.
//
// The table lives on the registry's own (public-schema) connection, not the
// identity connection, so it works unchanged whether identity data is in the
// app's public schema, the shared identity schema, or a separate identity
// database.
package repositories

import (
	"context"
	"database/sql"
	"time"
)

// UserTokenRevocationRepository manages per-user token-revocation watermarks.
type UserTokenRevocationRepository struct {
	db *sql.DB
}

// NewUserTokenRevocationRepository constructs a UserTokenRevocationRepository
// over the registry's domain connection.
func NewUserTokenRevocationRepository(db *sql.DB) *UserTokenRevocationRepository {
	return &UserTokenRevocationRepository{db: db}
}

// RevokeAllUserTokens invalidates every JWT issued to the user before now by
// moving the user's revocation watermark to the current time. Tokens issued
// after this call (e.g. a fresh login) validate normally.
func (r *UserTokenRevocationRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	query := `
		INSERT INTO user_token_revocations (user_id, revoked_before, updated_at)
		VALUES ($1, NOW(), NOW())
		ON CONFLICT (user_id) DO UPDATE
		SET revoked_before = EXCLUDED.revoked_before, updated_at = EXCLUDED.updated_at
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

// TokensRevokedSince reports whether tokens issued to the user at issuedAt are
// revoked, i.e. whether the user's watermark postdates the token's iat claim.
func (r *UserTokenRevocationRepository) TokensRevokedSince(ctx context.Context, userID string, issuedAt time.Time) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM user_token_revocations WHERE user_id = $1 AND revoked_before > $2)`
	var revoked bool
	err := r.db.QueryRowContext(ctx, query, userID, issuedAt).Scan(&revoked)
	return revoked, err
}

// CleanupExpiredWatermarks removes watermarks old enough that every token they
// could revoke has already expired naturally. maxTokenTTL should be at least
// the longest JWT lifetime the app issues (24h); a watermark older than that
// can no longer match any structurally valid token.
func (r *UserTokenRevocationRepository) CleanupExpiredWatermarks(ctx context.Context, maxTokenTTL time.Duration) error {
	query := `DELETE FROM user_token_revocations WHERE revoked_before < $1`
	_, err := r.db.ExecContext(ctx, query, time.Now().Add(-maxTokenTTL))
	return err
}
