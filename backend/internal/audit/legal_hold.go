// Package audit — legal_hold.go records which audit entries an investigation
// has asked to be preserved, so the retention sweep does not delete them.
//
// # What this file is and is not
//
// It is the WRITE side. The PRESERVE side — the predicate that actually stops
// a row being deleted — lives in terraform-suite-identity, because that is
// where the sweep is: store.WithLegalHolds turns this table into a NOT EXISTS
// inside DeleteAuditLogsBefore's batch selection.
//
// The two halves used to be a file apart and a repository apart, and neither
// was connected (#872). This file declared in its own header that it "prevents
// the audit retention cleanup job from deleting flagged log entries" while
// having no caller on either end, and the sweep it named had no hold predicate
// at all. Anyone adding an API over the old code would have produced a system
// where an operator places a hold, the UI confirms it, and the job deletes the
// evidence anyway.
//
// # The table is a migration now
//
// EnsureTable used to create it at startup "without requiring a numbered
// migration". That is the #864 class — schema the migration chain does not
// describe — and #871's guard tolerated it as credited runtime DDL. Migration
// 000057 creates it, store.LegalHoldTableDDL renders the shape, and
// TestMigration000057MatchesTheLibraryDDL holds the two together.
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrHoldNotFound is returned when a hold does not exist or is already
// released. Both are the same answer to "release this": there is nothing here
// still holding anything.
var ErrHoldNotFound = errors.New("legal hold not found or already released")

// LegalHold is one investigation's claim on a window of audit history.
//
// The window is INCLUSIVE at both ends, matching the sweep's `>=` and `<=`. A
// hold covering a single day is StartDate and EndDate on that day, not a
// half-open range the operator has to reason about.
type LegalHold struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Reason    string    `json:"reason,omitempty"`
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Active    bool      `json:"active"`

	// PlacedBy and ReleasedBy are user ids, nullable because a hold may be
	// placed by a principal with no user row behind it.
	PlacedBy   *string    `json:"placed_by,omitempty"`
	PlacedAt   time.Time  `json:"placed_at"`
	ReleasedBy *string    `json:"released_by,omitempty"`
	ReleasedAt *time.Time `json:"released_at,omitempty"`
}

// LegalHoldStore reads and writes the legal_holds table.
//
// IT MUST BE BUILT ON THE CONNECTION THAT REACHES audit_logs. The sweep's
// NOT EXISTS runs on the identity connection, so a store pointed at a different
// database would accept holds the sweep cannot see — every hold placed, a UI
// confirming each one, and the retention job deleting the rows regardless.
// router.go verifies that with store.VerifyLegalHoldTable before wiring either
// side, and refuses to run the sweep at all if it does not resolve.
type LegalHoldStore struct {
	db *sql.DB
}

// NewLegalHoldStore creates a new LegalHoldStore.
func NewLegalHoldStore(db *sql.DB) *LegalHoldStore {
	return &LegalHoldStore{db: db}
}

// Place records a new hold and returns it as stored.
//
// The id is generated here rather than by the database so the caller has it for
// the audit entry it writes alongside, without a second round trip.
func (s *LegalHoldStore) Place(ctx context.Context, hold *LegalHold) error {
	if hold.Name == "" {
		return fmt.Errorf("legal hold name is required")
	}
	if hold.EndDate.Before(hold.StartDate) {
		return fmt.Errorf("end_date must not be before start_date")
	}
	if hold.ID == "" {
		hold.ID = uuid.NewString()
	}

	const query = `
		INSERT INTO legal_holds (id, name, reason, start_date, end_date, placed_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING placed_at, active
	`
	return s.db.QueryRowContext(ctx, query,
		hold.ID, hold.Name, hold.Reason, hold.StartDate, hold.EndDate, hold.PlacedBy,
	).Scan(&hold.PlacedAt, &hold.Active)
}

// Release deactivates a hold, making the rows it covered deletable on the next
// sweep. The row is kept: it is the record of what was preserved and when, and
// deleting it would erase the evidence that evidence was held.
func (s *LegalHoldStore) Release(ctx context.Context, id string, releasedBy *string) (*LegalHold, error) {
	const query = `
		UPDATE legal_holds
		SET active = FALSE, released_at = now(), released_by = $2
		WHERE id = $1 AND active = TRUE
		RETURNING id, name, reason, start_date, end_date, active,
		          placed_by, placed_at, released_by, released_at
	`
	var h LegalHold
	err := s.db.QueryRowContext(ctx, query, id, releasedBy).Scan(
		&h.ID, &h.Name, &h.Reason, &h.StartDate, &h.EndDate, &h.Active,
		&h.PlacedBy, &h.PlacedAt, &h.ReleasedBy, &h.ReleasedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrHoldNotFound
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

const holdColumns = `id, name, reason, start_date, end_date, active,
	                 placed_by, placed_at, released_by, released_at`

// List returns holds newest first, optionally only those still in force.
func (s *LegalHoldStore) List(ctx context.Context, activeOnly bool) ([]LegalHold, error) {
	query := `SELECT ` + holdColumns + ` FROM legal_holds`
	if activeOnly {
		query += ` WHERE active = TRUE`
	}
	query += ` ORDER BY placed_at DESC, id ASC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	// Initialised, not nil: an empty list marshals as [] rather than null, so a
	// consumer can tell "no holds" from "the field is missing".
	holds := make([]LegalHold, 0)
	for rows.Next() {
		var h LegalHold
		if err := rows.Scan(&h.ID, &h.Name, &h.Reason, &h.StartDate, &h.EndDate, &h.Active,
			&h.PlacedBy, &h.PlacedAt, &h.ReleasedBy, &h.ReleasedAt); err != nil {
			return nil, err
		}
		holds = append(holds, h)
	}
	return holds, rows.Err()
}

// GetByID returns one hold.
func (s *LegalHoldStore) GetByID(ctx context.Context, id string) (*LegalHold, error) {
	var h LegalHold
	err := s.db.QueryRowContext(ctx, `SELECT `+holdColumns+` FROM legal_holds WHERE id = $1`, id).Scan(
		&h.ID, &h.Name, &h.Reason, &h.StartDate, &h.EndDate, &h.Active,
		&h.PlacedBy, &h.PlacedAt, &h.ReleasedBy, &h.ReleasedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrHoldNotFound
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}
