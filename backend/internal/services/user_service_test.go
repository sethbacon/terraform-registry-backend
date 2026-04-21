package services

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestNewUserService(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	svc := NewUserService(db)
	if svc == nil {
		t.Fatal("NewUserService returned nil")
	}
}

func TestExportUserData_UserNotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM users").
		WithArgs("nonexistent").
		WillReturnError(fmt.Errorf("sql: no rows in result set"))

	svc := NewUserService(db)
	_, err := svc.ExportUserData(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("ExportUserData() = nil, want error for missing user")
	}
}

func TestExportUserData_Success(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Now()
	oidcSub := "sub-123"

	// User query
	userRows := sqlmock.NewRows([]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}).
		AddRow("user-1", "test@example.com", "Test User", &oidcSub, now, now)
	mock.ExpectQuery("SELECT .+ FROM users WHERE id").
		WithArgs("user-1").
		WillReturnRows(userRows)

	// Memberships query
	memberRows := sqlmock.NewRows([]string{"org_id", "org_name", "role"}).
		AddRow("org-1", "Test Org", "admin")
	mock.ExpectQuery("SELECT .+ FROM organization_members").
		WithArgs("user-1").
		WillReturnRows(memberRows)

	// API keys query
	keyRows := sqlmock.NewRows([]string{"id", "name", "created_at", "expires_at", "last_used_at"}).
		AddRow("key-1", "My Key", now, nil, nil)
	mock.ExpectQuery("SELECT .+ FROM api_keys").
		WithArgs("user-1").
		WillReturnRows(keyRows)

	// Audit count
	auditRows := sqlmock.NewRows([]string{"count"}).AddRow(42)
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("user-1").
		WillReturnRows(auditRows)

	// Modules
	modRows := sqlmock.NewRows([]string{"id", "namespace", "name"}).
		AddRow("mod-1", "myorg", "vpc")
	mock.ExpectQuery("SELECT DISTINCT .+ FROM modules").
		WithArgs("user-1").
		WillReturnRows(modRows)

	// Providers
	provRows := sqlmock.NewRows([]string{"id", "namespace", "type"}).
		AddRow("prov-1", "myorg", "aws")
	mock.ExpectQuery("SELECT DISTINCT .+ FROM providers").
		WithArgs("user-1").
		WillReturnRows(provRows)

	svc := NewUserService(db)
	export, err := svc.ExportUserData(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ExportUserData() = %v", err)
	}

	if export.User.ID != "user-1" {
		t.Errorf("User.ID = %q, want user-1", export.User.ID)
	}
	if export.User.Email != "test@example.com" {
		t.Errorf("User.Email = %q, want test@example.com", export.User.Email)
	}
	if len(export.Memberships) != 1 {
		t.Errorf("len(Memberships) = %d, want 1", len(export.Memberships))
	}
	if len(export.APIKeys) != 1 {
		t.Errorf("len(APIKeys) = %d, want 1", len(export.APIKeys))
	}
	if export.AuditEntries != 42 {
		t.Errorf("AuditEntries = %d, want 42", export.AuditEntries)
	}
	if len(export.ModulesCreated) != 1 {
		t.Errorf("len(ModulesCreated) = %d, want 1", len(export.ModulesCreated))
	}
	if len(export.ProvidersCreated) != 1 {
		t.Errorf("len(ProvidersCreated) = %d, want 1", len(export.ProvidersCreated))
	}
}

func TestExportUserDataJSON(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Now()
	userRows := sqlmock.NewRows([]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}).
		AddRow("user-1", "test@example.com", "Test", nil, now, now)
	mock.ExpectQuery("SELECT .+ FROM users").WithArgs("user-1").WillReturnRows(userRows)

	// Empty result sets for the rest
	mock.ExpectQuery("SELECT .+ FROM organization_members").WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"a", "b", "c"}))
	mock.ExpectQuery("SELECT .+ FROM api_keys").WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"a", "b", "c", "d", "e"}))
	mock.ExpectQuery("SELECT COUNT").WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT DISTINCT .+ FROM modules").WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"a", "b", "c"}))
	mock.ExpectQuery("SELECT DISTINCT .+ FROM providers").WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"a", "b", "c"}))

	svc := NewUserService(db)
	data, err := svc.ExportUserDataJSON(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ExportUserDataJSON() = %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	user := m["user"].(map[string]interface{})
	if user["id"] != "user-1" {
		t.Errorf("JSON user.id = %v, want user-1", user["id"])
	}
}

func TestEraseUser_Success(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("UPDATE users").
		WithArgs("user-1", "erased-user-1@erased.local").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM api_keys").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("DELETE FROM organization_members").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO revoked_tokens").
		WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	svc := NewUserService(db)
	err := svc.EraseUser(context.Background(), "user-1", "admin-1")
	if err != nil {
		t.Fatalf("EraseUser() = %v", err)
	}
}

func TestEraseUser_UserNotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectRollback()

	svc := NewUserService(db)
	err := svc.EraseUser(context.Background(), "missing", "admin")
	if err == nil {
		t.Fatal("EraseUser() for missing user = nil, want error")
	}
}

func TestEraseUser_BeginTxError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin().WillReturnError(fmt.Errorf("tx error"))

	svc := NewUserService(db)
	err := svc.EraseUser(context.Background(), "user-1", "admin")
	if err == nil {
		t.Fatal("EraseUser() with tx error = nil, want error")
	}
}
