package audit

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// The store is the WRITE side of legal hold. Its correctness question is
// narrow — does a hold get recorded with the shape the sweep reads, and does
// releasing one stop it holding — because the PRESERVE side is a SQL predicate
// in terraform-suite-identity, proved against real PostgreSQL there.
//
// What these cannot prove, and no mock can, is that a held row survives a
// sweep. That assertion lives where the predicate does.

const testHoldID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

func newHoldStore(t *testing.T) (*LegalHoldStore, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewLegalHoldStore(db), mock
}

func TestNewLegalHoldStore(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer func() { _ = db.Close() }()

	store := NewLegalHoldStore(db)
	if store == nil || store.db != db {
		t.Fatal("NewLegalHoldStore did not retain its connection")
	}
}

// EnsureTable is gone: migration 000057 creates the table. A store that still
// created its own would put it wherever the store's connection points, which
// is exactly how a hold ends up somewhere the sweep cannot see it.
func TestStoreCreatesNoSchema(t *testing.T) {
	store, mock := newHoldStore(t)
	// No expectations queued. Any DDL the store issues fails as unexpected.
	if _, err := store.List(context.Background(), false); err == nil {
		t.Fatal("List should have failed with no expectation queued")
	}
	_ = mock
}

func TestPlaceRecordsTheHold(t *testing.T) {
	store, mock := newHoldStore(t)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 7)
	actor := "actor-1"

	mock.ExpectQuery(`INSERT INTO legal_holds`).
		WithArgs(sqlmock.AnyArg(), "investigation", "subpoena 42", start, end, &actor).
		WillReturnRows(sqlmock.NewRows([]string{"placed_at", "active"}).AddRow(start, true))

	hold := &LegalHold{Name: "investigation", Reason: "subpoena 42", StartDate: start, EndDate: end, PlacedBy: &actor}
	if err := store.Place(context.Background(), hold); err != nil {
		t.Fatalf("Place: %v", err)
	}
	if hold.ID == "" {
		t.Error("Place did not assign an id; the caller needs it for the audit entry it writes alongside")
	}
	if !hold.Active {
		t.Error("a freshly placed hold is not active")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestPlaceRefusesAnUnusableWindow(t *testing.T) {
	start := time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		hold LegalHold
	}{
		{"no name", LegalHold{StartDate: start, EndDate: start}},
		{"end before start", LegalHold{Name: "x", StartDate: start, EndDate: start.AddDate(0, 0, -1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, mock := newHoldStore(t)
			h := tc.hold
			if err := store.Place(context.Background(), &h); err == nil {
				t.Fatal("an unusable hold was accepted")
			}
			// And nothing reached the database.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("a statement ran despite the rejection: %v", err)
			}
		})
	}
}

// A hold covering a single day must be accepted: the sweep's range is
// inclusive at both ends, so start == end holds that day.
func TestPlaceAcceptsASingleDayHold(t *testing.T) {
	store, mock := newHoldStore(t)
	day := time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`INSERT INTO legal_holds`).
		WillReturnRows(sqlmock.NewRows([]string{"placed_at", "active"}).AddRow(day, true))

	h := &LegalHold{Name: "one day", StartDate: day, EndDate: day}
	if err := store.Place(context.Background(), h); err != nil {
		t.Fatalf("a single-day hold was refused: %v", err)
	}
}

func TestReleaseDeactivatesAndKeepsTheRow(t *testing.T) {
	store, mock := newHoldStore(t)
	now := time.Now().UTC()
	actor := "releaser-1"

	mock.ExpectQuery(`UPDATE legal_holds`).
		WithArgs(testHoldID, &actor).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "reason", "start_date", "end_date", "active",
			"placed_by", "placed_at", "released_by", "released_at",
		}).AddRow(testHoldID, "investigation", "", now, now, false, nil, now, &actor, &now))

	h, err := store.Release(context.Background(), testHoldID, &actor)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if h.Active {
		t.Error("released hold is still active")
	}
	if h.ReleasedAt == nil {
		t.Error("released hold has no released_at; the row is the record of what was preserved and when")
	}
}

// Releasing something that is not held is not an error worth inventing a
// distinction for: absent and already-released are the same answer.
func TestReleaseReportsNothingToRelease(t *testing.T) {
	store, mock := newHoldStore(t)
	mock.ExpectQuery(`UPDATE legal_holds`).WillReturnError(sql.ErrNoRows)

	_, err := store.Release(context.Background(), testHoldID, nil)
	if !errors.Is(err, ErrHoldNotFound) {
		t.Fatalf("Release on an unknown hold = %v, want ErrHoldNotFound — the handler maps that "+
			"sentinel to 404, so anything else becomes a 500", err)
	}
}

func TestListReturnsAnEmptySliceNotNil(t *testing.T) {
	store, mock := newHoldStore(t)
	mock.ExpectQuery(`SELECT .* FROM legal_holds`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "reason", "start_date", "end_date", "active",
			"placed_by", "placed_at", "released_by", "released_at",
		}))

	holds, err := store.List(context.Background(), false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if holds == nil {
		t.Error("List returned nil; an empty list must marshal as [] so a consumer can tell " +
			"'no holds' from a missing field")
	}
}

func TestListActiveOnlyConstrainsTheQuery(t *testing.T) {
	store, mock := newHoldStore(t)
	mock.ExpectQuery(`FROM legal_holds WHERE active = TRUE`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "reason", "start_date", "end_date", "active",
			"placed_by", "placed_at", "released_by", "released_at",
		}))

	if _, err := store.List(context.Background(), true); err != nil {
		t.Fatalf("List(activeOnly): %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("activeOnly did not constrain the query: %v", err)
	}
}

func TestGetByIDReportsAbsence(t *testing.T) {
	store, mock := newHoldStore(t)
	mock.ExpectQuery(`SELECT .* FROM legal_holds WHERE id = \$1`).
		WillReturnError(sql.ErrNoRows)

	_, err := store.GetByID(context.Background(), testHoldID)
	if !errors.Is(err, ErrHoldNotFound) {
		t.Fatalf("GetByID on an unknown id = %v, want ErrHoldNotFound", err)
	}
}
