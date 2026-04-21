package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestNewLegalHoldStore(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	store := NewLegalHoldStore(db)
	if store == nil {
		t.Fatal("NewLegalHoldStore returned nil")
	}
	if store.db != db {
		t.Error("store.db not set correctly")
	}
}

func TestLegalHoldStore_EnsureTable(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS legal_holds").
		WillReturnResult(sqlmock.NewResult(0, 0))

	store := NewLegalHoldStore(db)
	err := store.EnsureTable(context.Background())
	if err != nil {
		t.Fatalf("EnsureTable() = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestLegalHoldStore_Create_Success(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "created_at", "active"}).
		AddRow(int64(1), now, true)

	mock.ExpectQuery("INSERT INTO legal_holds").
		WithArgs("test hold", "description", "admin", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	store := NewLegalHoldStore(db)
	hold := &LegalHold{
		Name:        "test hold",
		Description: "description",
		CreatedBy:   "admin",
		StartDate:   now.Add(-24 * time.Hour),
		EndDate:     now.Add(24 * time.Hour),
	}

	err := store.Create(context.Background(), hold)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if hold.ID != 1 {
		t.Errorf("ID = %d, want 1", hold.ID)
	}
	if !hold.Active {
		t.Error("Active = false, want true")
	}
}

func TestLegalHoldStore_Create_EmptyName(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	store := NewLegalHoldStore(db)
	hold := &LegalHold{
		StartDate: time.Now(),
		EndDate:   time.Now().Add(time.Hour),
	}

	err := store.Create(context.Background(), hold)
	if err == nil {
		t.Fatal("Create() with empty name = nil, want error")
	}
}

func TestLegalHoldStore_Create_InvalidDates(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	store := NewLegalHoldStore(db)
	hold := &LegalHold{
		Name:      "test",
		StartDate: time.Now().Add(time.Hour),
		EndDate:   time.Now(), // end before start
	}

	err := store.Create(context.Background(), hold)
	if err == nil {
		t.Fatal("Create() with start > end = nil, want error")
	}
}

func TestLegalHoldStore_Release_Success(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectExec("UPDATE legal_holds").
		WithArgs(int64(1), "admin").
		WillReturnResult(sqlmock.NewResult(0, 1))

	store := NewLegalHoldStore(db)
	err := store.Release(context.Background(), 1, "admin")
	if err != nil {
		t.Fatalf("Release() = %v", err)
	}
}

func TestLegalHoldStore_Release_NotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectExec("UPDATE legal_holds").
		WithArgs(int64(99), "admin").
		WillReturnResult(sqlmock.NewResult(0, 0))

	store := NewLegalHoldStore(db)
	err := store.Release(context.Background(), 99, "admin")
	if err == nil {
		t.Fatal("Release() of non-existent hold = nil, want error")
	}
}

func TestLegalHoldStore_Release_DBError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectExec("UPDATE legal_holds").
		WithArgs(int64(1), "admin").
		WillReturnError(fmt.Errorf("db error"))

	store := NewLegalHoldStore(db)
	err := store.Release(context.Background(), 1, "admin")
	if err == nil {
		t.Fatal("Release() with DB error = nil, want error")
	}
}

func TestLegalHoldStore_List_All(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "name", "description", "created_by", "created_at", "start_date", "end_date", "active", "released_at", "released_by"}).
		AddRow(int64(1), "hold1", "desc1", "admin", now, now, now, true, nil, "").
		AddRow(int64(2), "hold2", "desc2", "admin", now, now, now, false, &now, "admin")

	mock.ExpectQuery("SELECT .+ FROM legal_holds ORDER BY").
		WillReturnRows(rows)

	store := NewLegalHoldStore(db)
	holds, err := store.List(context.Background(), false)
	if err != nil {
		t.Fatalf("List(false) = %v", err)
	}
	if len(holds) != 2 {
		t.Fatalf("len(holds) = %d, want 2", len(holds))
	}
	if holds[0].Name != "hold1" {
		t.Errorf("holds[0].Name = %q, want hold1", holds[0].Name)
	}
}

func TestLegalHoldStore_List_ActiveOnly(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "name", "description", "created_by", "created_at", "start_date", "end_date", "active", "released_at", "released_by"}).
		AddRow(int64(1), "active-hold", "", "admin", now, now, now, true, nil, "")

	mock.ExpectQuery("WHERE active = TRUE").
		WillReturnRows(rows)

	store := NewLegalHoldStore(db)
	holds, err := store.List(context.Background(), true)
	if err != nil {
		t.Fatalf("List(true) = %v", err)
	}
	if len(holds) != 1 {
		t.Fatalf("len(holds) = %d, want 1", len(holds))
	}
}

func TestLegalHoldStore_GetByID(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "name", "description", "created_by", "created_at", "start_date", "end_date", "active", "released_at", "released_by"}).
		AddRow(int64(1), "test", "desc", "admin", now, now, now, true, nil, "")

	mock.ExpectQuery("SELECT .+ FROM legal_holds WHERE id").
		WithArgs(int64(1)).
		WillReturnRows(rows)

	store := NewLegalHoldStore(db)
	hold, err := store.GetByID(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetByID() = %v", err)
	}
	if hold.Name != "test" {
		t.Errorf("Name = %q, want test", hold.Name)
	}
}

func TestLegalHoldStore_IsDateRangeHeld(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	rows := sqlmock.NewRows([]string{"exists"}).AddRow(true)
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	store := NewLegalHoldStore(db)
	held, err := store.IsDateRangeHeld(context.Background(), time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IsDateRangeHeld() = %v", err)
	}
	if !held {
		t.Error("held = false, want true")
	}
}

func TestLegalHoldStore_IsDateRangeHeld_NotHeld(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	rows := sqlmock.NewRows([]string{"exists"}).AddRow(false)
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(rows)

	store := NewLegalHoldStore(db)
	held, err := store.IsDateRangeHeld(context.Background(), time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IsDateRangeHeld() = %v", err)
	}
	if held {
		t.Error("held = true, want false")
	}
}

func TestLegalHoldStore_HeldDateRanges(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	start1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	start2 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	end2 := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)

	rows := sqlmock.NewRows([]string{"start_date", "end_date"}).
		AddRow(start1, end1).
		AddRow(start2, end2)

	mock.ExpectQuery("SELECT start_date, end_date FROM legal_holds WHERE active = TRUE").
		WillReturnRows(rows)

	store := NewLegalHoldStore(db)
	ranges, err := store.HeldDateRanges(context.Background())
	if err != nil {
		t.Fatalf("HeldDateRanges() = %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("len(ranges) = %d, want 2", len(ranges))
	}
	if !ranges[0][0].Equal(start1) {
		t.Errorf("ranges[0][0] = %v, want %v", ranges[0][0], start1)
	}
}
