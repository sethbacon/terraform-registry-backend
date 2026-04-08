package repositories

import (
	"context"
	"database/sql"
	"time"
)

// TokenRepository handles JWT revocation database operations
type TokenRepository struct {
	db *sql.DB
}

// NewTokenRepository creates a new TokenRepository
func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// RevokeToken adds a JTI to the revocation list
func (r *TokenRepository) RevokeToken(ctx context.Context, jti, userID string, expiresAt time.Time) error {
	query := `
		INSERT INTO revoked_tokens (jti, user_id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (jti) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, jti, userID, expiresAt)
	return err
}

// IsTokenRevoked checks whether a JTI has been revoked
func (r *TokenRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, jti).Scan(&exists)
	return exists, err
}

// CleanupExpiredRevocations removes entries whose tokens have already expired
func (r *TokenRepository) CleanupExpiredRevocations(ctx context.Context) error {
	query := `DELETE FROM revoked_tokens WHERE expires_at < NOW()`
	_, err := r.db.ExecContext(ctx, query)
	return err
}
