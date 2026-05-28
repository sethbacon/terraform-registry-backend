// releases_gpg_key_repository.go is the persistence layer for the cached
// release-signing GPG keys table populated by the ReleasesKeyRefreshJob.
// Get returns nil/nil when no row has been cached yet so callers can fall
// back to the embedded snapshot without conflating "no cache" with errors.
package repositories

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// ReleasesGPGKeyRepository handles reads and upserts against releases_gpg_keys.
type ReleasesGPGKeyRepository struct {
	db *sqlx.DB
}

// NewReleasesGPGKeyRepository constructs a ReleasesGPGKeyRepository.
func NewReleasesGPGKeyRepository(db *sqlx.DB) *ReleasesGPGKeyRepository {
	return &ReleasesGPGKeyRepository{db: db}
}

// Get returns the cached key for the given tool, or nil if none has been
// written yet.
func (r *ReleasesGPGKeyRepository) Get(ctx context.Context, tool string) (*models.ReleasesGPGKey, error) {
	var row models.ReleasesGPGKey
	query := `
		SELECT tool, armored_key, primary_fpr, key_expires_at, source_url, fetched_at
		FROM releases_gpg_keys
		WHERE tool = $1
	`
	err := r.db.GetContext(ctx, &row, query, tool)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// Upsert writes the cached key for a tool, replacing any existing row.
// The caller is responsible for fingerprint validation — this layer trusts
// its input. fetched_at is always set to NOW() server-side.
func (r *ReleasesGPGKeyRepository) Upsert(ctx context.Context, in *models.ReleasesGPGKey) error {
	query := `
		INSERT INTO releases_gpg_keys (
			tool, armored_key, primary_fpr, key_expires_at, source_url, fetched_at
		) VALUES (
			$1, $2, $3, $4, $5, NOW()
		)
		ON CONFLICT (tool) DO UPDATE SET
			armored_key    = EXCLUDED.armored_key,
			primary_fpr    = EXCLUDED.primary_fpr,
			key_expires_at = EXCLUDED.key_expires_at,
			source_url     = EXCLUDED.source_url,
			fetched_at     = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		in.Tool, in.ArmoredKey, in.PrimaryFingerprint, in.KeyExpiresAt, in.SourceURL,
	)
	return err
}
