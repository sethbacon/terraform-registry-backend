// Package audit — legal_hold.go implements legal hold functionality that
// prevents the audit retention cleanup job from deleting flagged log entries.
// coverage:skip:requires-postgres
// Legal holds are used during compliance investigations or litigation to
// preserve audit evidence.
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// LegalHold represents a hold placed on audit log entries to prevent deletion.
type LegalHold struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	StartDate   time.Time  `json:"start_date"`
	EndDate     time.Time  `json:"end_date"`
	Active      bool       `json:"active"`
	ReleasedAt  *time.Time `json:"released_at,omitempty"`
	ReleasedBy  string     `json:"released_by,omitempty"`
}

// LegalHoldStore manages legal hold records in the database.
type LegalHoldStore struct {
	db *sql.DB
}

// NewLegalHoldStore creates a new LegalHoldStore.
func NewLegalHoldStore(db *sql.DB) *LegalHoldStore {
	return &LegalHoldStore{db: db}
}

// EnsureTable creates the legal_holds table if it does not exist.
// This is called during application startup so the feature is always available
// without requiring a numbered migration.
func (s *LegalHoldStore) EnsureTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS legal_holds (
			id            BIGSERIAL PRIMARY KEY,
			name          TEXT NOT NULL,
			description   TEXT DEFAULT '',
			created_by    TEXT NOT NULL,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			start_date    TIMESTAMPTZ NOT NULL,
			end_date      TIMESTAMPTZ NOT NULL,
			active        BOOLEAN NOT NULL DEFAULT TRUE,
			released_at   TIMESTAMPTZ,
			released_by   TEXT DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_legal_holds_active ON legal_holds (active) WHERE active = TRUE;
	`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

// Create inserts a new legal hold.
func (s *LegalHoldStore) Create(ctx context.Context, hold *LegalHold) error {
	if hold.Name == "" {
		return fmt.Errorf("legal hold name is required")
	}
	if hold.StartDate.After(hold.EndDate) {
		return fmt.Errorf("start_date must be before end_date")
	}

	query := `
		INSERT INTO legal_holds (name, description, created_by, start_date, end_date)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, active
	`
	return s.db.QueryRowContext(ctx, query,
		hold.Name, hold.Description, hold.CreatedBy, hold.StartDate, hold.EndDate,
	).Scan(&hold.ID, &hold.CreatedAt, &hold.Active)
}

// Release deactivates a legal hold, allowing covered entries to be cleaned up.
func (s *LegalHoldStore) Release(ctx context.Context, id int64, releasedBy string) error {
	query := `
		UPDATE legal_holds
		SET active = FALSE, released_at = NOW(), released_by = $2
		WHERE id = $1 AND active = TRUE
	`
	result, err := s.db.ExecContext(ctx, query, id, releasedBy)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("legal hold %d not found or already released", id)
	}
	return nil
}

// List returns all legal holds, optionally filtered to only active ones.
func (s *LegalHoldStore) List(ctx context.Context, activeOnly bool) ([]LegalHold, error) {
	query := `SELECT id, name, description, created_by, created_at, start_date, end_date, active, released_at, released_by FROM legal_holds`
	if activeOnly {
		query += ` WHERE active = TRUE`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var holds []LegalHold
	for rows.Next() {
		var h LegalHold
		if err := rows.Scan(&h.ID, &h.Name, &h.Description, &h.CreatedBy, &h.CreatedAt,
			&h.StartDate, &h.EndDate, &h.Active, &h.ReleasedAt, &h.ReleasedBy); err != nil {
			return nil, err
		}
		holds = append(holds, h)
	}
	return holds, rows.Err()
}

// GetByID returns a single legal hold.
func (s *LegalHoldStore) GetByID(ctx context.Context, id int64) (*LegalHold, error) {
	query := `SELECT id, name, description, created_by, created_at, start_date, end_date, active, released_at, released_by FROM legal_holds WHERE id = $1`
	var h LegalHold
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&h.ID, &h.Name, &h.Description, &h.CreatedBy, &h.CreatedAt,
		&h.StartDate, &h.EndDate, &h.Active, &h.ReleasedAt, &h.ReleasedBy,
	)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// IsDateRangeHeld checks whether any active legal hold covers the given date range.
// Used by the retention cleanup job to skip deletion of held entries.
func (s *LegalHoldStore) IsDateRangeHeld(ctx context.Context, from, to time.Time) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM legal_holds
			WHERE active = TRUE
			  AND start_date <= $2
			  AND end_date >= $1
		)
	`
	var held bool
	err := s.db.QueryRowContext(ctx, query, from, to).Scan(&held)
	return held, err
}

// HeldDateRanges returns all active hold date ranges. The retention job uses
// this to exclude entries that fall within any held range.
func (s *LegalHoldStore) HeldDateRanges(ctx context.Context) ([][2]time.Time, error) {
	query := `SELECT start_date, end_date FROM legal_holds WHERE active = TRUE ORDER BY start_date`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ranges [][2]time.Time
	for rows.Next() {
		var r [2]time.Time
		if err := rows.Scan(&r[0], &r[1]); err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	return ranges, rows.Err()
}
