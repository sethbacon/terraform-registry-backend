package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

// devUserCols matches the users table columns for positional scans in UserRepository
var devUserCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

func newDevRouter(t *testing.T, userScopes []string) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewDevHandlers(&config.Config{}, db)
	r := gin.New()

	if len(userScopes) > 0 {
		r.Use(func(c *gin.Context) {
			c.Set("scopes", userScopes)
			c.Next()
		})
	}

	r.POST("/dev/impersonate/:user_id", h.ImpersonateUserHandler())
	r.GET("/dev/users", h.ListUsersForImpersonationHandler())
	r.POST("/dev/login", h.DevLoginHandler())
	r.GET("/dev/status", h.DevStatusHandler())
	return mock, r
}

// ---------------------------------------------------------------------------
// IsDevMode
// ---------------------------------------------------------------------------

func TestIsDevMode_True(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	if !IsDevMode() {
		t.Error("expected IsDevMode() = true when DEV_MODE=true")
	}
}

func TestIsDevMode_OneValue(t *testing.T) {
	t.Setenv("DEV_MODE", "1")
	if !IsDevMode() {
		t.Error("expected IsDevMode() = true when DEV_MODE=1")
	}
}

func TestIsDevMode_False(t *testing.T) {
	os.Unsetenv("DEV_MODE")
	if IsDevMode() {
		t.Error("expected IsDevMode() = false when DEV_MODE not set")
	}
}

// ---------------------------------------------------------------------------
// DevModeMiddleware
// ---------------------------------------------------------------------------

func TestDevModeMiddleware_Blocked(t *testing.T) {
	os.Unsetenv("DEV_MODE")
	r := gin.New()
	r.GET("/test", DevModeMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestDevModeMiddleware_Allowed(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	r := gin.New()
	r.GET("/test", DevModeMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DevStatusHandler
// ---------------------------------------------------------------------------

func TestDevStatus(t *testing.T) {
	os.Unsetenv("DEV_MODE")
	_, r := newDevRouter(t, nil)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/dev/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)
	if _, ok := resp["dev_mode"]; !ok {
		t.Error("response missing 'dev_mode' key")
	}
}

// ---------------------------------------------------------------------------
// DevLoginHandler
// ---------------------------------------------------------------------------

func TestDevLogin_UserNotFound(t *testing.T) {
	mock, r := newDevRouter(t, nil)
	// GetUserByEmail returns no rows
	mock.ExpectQuery("SELECT.*FROM users WHERE email").
		WillReturnRows(sqlmock.NewRows(devUserCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/dev/login", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDevLogin_DBError(t *testing.T) {
	mock, r := newDevRouter(t, nil)
	mock.ExpectQuery("SELECT.*FROM users WHERE email").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/dev/login", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDevLogin_Success(t *testing.T) {
	t.Setenv("TFR_JWT_SECRET", "test-secret-key-that-is-at-least-32-characters-long")
	mock, r := newDevRouter(t, nil)

	now := time.Now()

	// GetUserByEmail returns the dev admin user
	mock.ExpectQuery("SELECT.*FROM users WHERE email").
		WillReturnRows(sqlmock.NewRows(devUserCols).
			AddRow("user-1", "admin@dev.local", "Dev Admin", nil, now, now))

	// GetUserCombinedScopes -> GetUserMemberships (empty)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipSQLCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/dev/login", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["token"] == nil {
		t.Error("response missing 'token' key")
	}
	if resp["user"] == nil {
		t.Error("response missing 'user' key")
	}
	if resp["expires_in"] == nil {
		t.Error("response missing 'expires_in' key")
	}
}

// ---------------------------------------------------------------------------
// ImpersonateUserHandler
// ---------------------------------------------------------------------------

func TestImpersonate_NoScopes(t *testing.T) {
	_, r := newDevRouter(t, nil) // no scopes middleware

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/dev/impersonate/user-123", nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestImpersonate_NotAdmin(t *testing.T) {
	_, r := newDevRouter(t, []string{"modules:read"})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/dev/impersonate/user-123", nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestImpersonate_TargetUserNotFound(t *testing.T) {
	mock, r := newDevRouter(t, []string{"admin"})
	// GetUserByID returns no rows
	mock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(devUserCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/dev/impersonate/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestImpersonate_Success(t *testing.T) {
	t.Setenv("TFR_JWT_SECRET", "test-secret-key-that-is-at-least-32-characters-long")
	mock, r := newDevRouter(t, []string{"admin"})

	now := time.Now()

	// GetUserByID returns the target user
	mock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(devUserCols).
			AddRow(knownUUID, "target@example.com", "Target User", nil, now, now))

	// GetUserCombinedScopes -> GetUserMemberships (empty)
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipSQLCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/dev/impersonate/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["token"] == nil {
		t.Error("response missing 'token' key")
	}
	if resp["user"] == nil {
		t.Error("response missing 'user' key")
	}
	if resp["message"] == nil {
		t.Error("response missing 'message' key")
	}
}

// ---------------------------------------------------------------------------
// ListUsersForImpersonationHandler
// ---------------------------------------------------------------------------

func TestListDevUsers_NoScopes(t *testing.T) {
	_, r := newDevRouter(t, nil)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/dev/users", nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestListDevUsers_NotAdmin(t *testing.T) {
	_, r := newDevRouter(t, []string{"modules:read"})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/dev/users", nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestListDevUsers_DBError(t *testing.T) {
	mock, r := newDevRouter(t, []string{"admin"})
	mock.ExpectQuery("SELECT.*FROM users").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/dev/users", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListDevUsers_Empty(t *testing.T) {
	mock, r := newDevRouter(t, []string{"admin"})
	// ListUsers first runs COUNT(*) then the paginated SELECT
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(sqlmock.NewRows(devUserCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/dev/users", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestListDevUsers_Success(t *testing.T) {
	mock, r := newDevRouter(t, []string{"admin"})

	now := time.Now()

	// ListUsers: COUNT then SELECT returning one user
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM users.*ORDER BY").
		WillReturnRows(sqlmock.NewRows(devUserCols).
			AddRow("user-1", "alice@example.com", "Alice", nil, now, now))

	// GetUserWithOrgRoles for user-1:
	// 1. GetUserByID
	mock.ExpectQuery("SELECT.*FROM users WHERE id").
		WillReturnRows(sqlmock.NewRows(devUserCols).
			AddRow("user-1", "alice@example.com", "Alice", nil, now, now))
	// 2. membership query with a role
	mock.ExpectQuery("SELECT.*FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipSQLCols).
			AddRow("org-1", "default", "rt-1", now, "admin", "Administrator", `["admin"]`))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/dev/users", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["users"] == nil {
		t.Error("response missing 'users' key")
	}
	if resp["dev_mode"] == nil {
		t.Error("response missing 'dev_mode' key")
	}
	users, ok := resp["users"].([]interface{})
	if !ok {
		t.Fatal("'users' is not an array")
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}
	u, ok := users[0].(map[string]interface{})
	if !ok {
		t.Fatal("user entry is not an object")
	}
	if u["primary_role"] != "Administrator" {
		t.Errorf("primary_role = %v, want Administrator", u["primary_role"])
	}
}
