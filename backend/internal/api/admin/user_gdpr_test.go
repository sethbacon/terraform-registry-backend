package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

func TestNewGDPRHandlers(t *testing.T) {
	h := NewGDPRHandlers(nil)
	if h == nil {
		t.Fatal("NewGDPRHandlers returned nil")
	}
}

func gdprRouter(h *GDPRHandlers) *gin.Engine {
	r := gin.New()
	r.GET("/api/v1/admin/users/:id/export", h.ExportUserDataHandler())
	r.POST("/api/v1/admin/users/:id/erase", func(c *gin.Context) {
		c.Set("user_id", "admin-1")
		c.Next()
	}, h.EraseUserHandler())
	return r
}

func TestExportUserDataHandler_Success(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	now := time.Now()
	mock.ExpectQuery("SELECT .+ FROM users").WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}).
			AddRow("user-1", "test@example.com", "Test", nil, now, now))
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

	svc := services.NewUserService(db)
	h := NewGDPRHandlers(svc)
	r := gdprRouter(h)

	req := httptest.NewRequest("GET", "/api/v1/admin/users/user-1/export", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd == "" {
		t.Error("missing Content-Disposition header")
	}
}

func TestExportUserDataHandler_NotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery("SELECT .+ FROM users").WithArgs("missing").
		WillReturnError(fmt.Errorf("sql: no rows"))

	svc := services.NewUserService(db)
	h := NewGDPRHandlers(svc)
	r := gdprRouter(h)

	req := httptest.NewRequest("GET", "/api/v1/admin/users/missing/export", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestEraseUserHandler_Success(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT EXISTS").WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("UPDATE users").
		WithArgs("user-1", "erased-user-1@erased.local").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM api_keys").WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("DELETE FROM organization_members").WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO revoked_tokens").WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	svc := services.NewUserService(db)
	h := NewGDPRHandlers(svc)
	r := gdprRouter(h)

	req := httptest.NewRequest("POST", "/api/v1/admin/users/user-1/erase", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["user_id"] != "user-1" {
		t.Errorf("body.user_id = %v, want user-1", body["user_id"])
	}
}

func TestEraseUserHandler_NotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT EXISTS").WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectRollback()

	svc := services.NewUserService(db)
	h := NewGDPRHandlers(svc)
	r := gdprRouter(h)

	req := httptest.NewRequest("POST", "/api/v1/admin/users/missing/erase", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestEraseUserHandler_NoAuthContext(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT EXISTS").WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("UPDATE users").
		WithArgs("user-1", "erased-user-1@erased.local").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM api_keys").WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("DELETE FROM organization_members").WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO revoked_tokens").WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	svc := services.NewUserService(db)
	h := NewGDPRHandlers(svc)

	// Router without setting user_id in context — should default to "system"
	r := gin.New()
	r.POST("/api/v1/admin/users/:id/erase", h.EraseUserHandler())

	req := httptest.NewRequest("POST", "/api/v1/admin/users/user-1/erase", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
