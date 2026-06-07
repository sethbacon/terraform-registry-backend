package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// fakeExecer records ExecContext calls and returns a configurable error. It
// satisfies systemRoleTemplateExecer without a live database.
type fakeExecer struct {
	calls []seedExecCall
	err   error
}

type seedExecCall struct {
	query string
	args  []any
}

func (f *fakeExecer) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	f.calls = append(f.calls, seedExecCall{query: query, args: args})
	return nil, f.err
}

func TestSeedSystemRoleTemplates_UpsertsEachTemplate(t *testing.T) {
	desc := "Can upload and manage modules and providers"
	templates := []models.RoleTemplate{
		{Name: "admin", DisplayName: "Administrator", Scopes: []string{"admin"}},
		{Name: "publisher", DisplayName: "Publisher", Description: &desc, Scopes: []string{"modules:read", "modules:write"}},
	}

	f := &fakeExecer{}
	if err := SeedSystemRoleTemplates(context.Background(), f, templates); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(f.calls) != len(templates) {
		t.Fatalf("expected %d Exec calls, got %d", len(templates), len(f.calls))
	}
	for i, call := range f.calls {
		if call.query != upsertSystemRoleTemplateQuery {
			t.Errorf("call %d: query did not match the upsert statement", i)
		}
		if len(call.args) != 4 {
			t.Fatalf("call %d: expected 4 args, got %d", i, len(call.args))
		}
		if call.args[0] != templates[i].Name {
			t.Errorf("call %d: name arg = %v, want %v", i, call.args[0], templates[i].Name)
		}
		if call.args[1] != templates[i].DisplayName {
			t.Errorf("call %d: display_name arg = %v, want %v", i, call.args[1], templates[i].DisplayName)
		}
		// Description (*string) passes through by pointer.
		if call.args[2] != templates[i].Description {
			t.Errorf("call %d: description arg did not pass through", i)
		}
		// Scopes are JSON-encoded for the JSONB column.
		scopesJSON, ok := call.args[3].([]byte)
		if !ok {
			t.Fatalf("call %d: scopes arg is %T, want []byte", i, call.args[3])
		}
		var gotScopes []string
		if err := json.Unmarshal(scopesJSON, &gotScopes); err != nil {
			t.Fatalf("call %d: scopes arg is not valid JSON: %v", i, err)
		}
		if !reflect.DeepEqual(gotScopes, templates[i].Scopes) {
			t.Errorf("call %d: scopes = %v, want %v", i, gotScopes, templates[i].Scopes)
		}
	}
}

// TestSeedSystemRoleTemplates_GuardedUpsertSQL locks the shape of the bootstrap
// write: it must be a guarded ON CONFLICT upsert that reaches is_system rows and
// no-ops when nothing changed.
func TestSeedSystemRoleTemplates_GuardedUpsertSQL(t *testing.T) {
	q := upsertSystemRoleTemplateQuery
	for _, want := range []string{
		"INSERT INTO role_templates",
		"ON CONFLICT (name) DO UPDATE SET",
		"is_system    = true",
		"IS DISTINCT FROM",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("upsert query is missing %q", want)
		}
	}
}

func TestSeedSystemRoleTemplates_PropagatesError(t *testing.T) {
	f := &fakeExecer{err: errors.New("db unavailable")}
	templates := []models.RoleTemplate{{Name: "viewer", Scopes: []string{"modules:read"}}}

	err := SeedSystemRoleTemplates(context.Background(), f, templates)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "viewer") {
		t.Errorf("error should name the failing role template, got: %v", err)
	}
}

func TestSeedSystemRoleTemplates_EmptyTemplates(t *testing.T) {
	f := &fakeExecer{}
	if err := SeedSystemRoleTemplates(context.Background(), f, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("expected no Exec calls for empty templates, got %d", len(f.calls))
	}
}

// TestSeedSystemRoleTemplates_Idempotent_NoOpReRun drives a real *sql.DB via
// sqlmock to assert the seed executes the guarded upsert once per template, and
// that a same-value re-run is a no-op: the guarded ON CONFLICT update affects 0
// rows (Postgres "INSERT 0 0"), which the seed tolerates without error.
func TestSeedSystemRoleTemplates_Idempotent_NoOpReRun(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	templates := models.PredefinedRoleTemplates()

	// First run: every template upsert inserts a row (RowsAffected = 1).
	for range templates {
		mock.ExpectExec("INSERT INTO role_templates").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	// Second run with identical values: the guarded WHERE suppresses every write,
	// so each upsert reports 0 rows affected — the steady-state no-op.
	for range templates {
		mock.ExpectExec("INSERT INTO role_templates").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 0))
	}

	if err := SeedSystemRoleTemplates(context.Background(), db, templates); err != nil {
		t.Fatalf("first seed run: unexpected error: %v", err)
	}
	if err := SeedSystemRoleTemplates(context.Background(), db, templates); err != nil {
		t.Fatalf("re-run seed: unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
