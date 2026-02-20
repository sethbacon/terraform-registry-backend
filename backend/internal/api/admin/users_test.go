package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---------------------------------------------------------------------------
// Test setup helpers
// ---------------------------------------------------------------------------

// userSQLCols are the columns returned by user SELECT queries.
var userSQLCols = []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}

// orgSQLCols are the columns returned by organization SELECT queries.
var orgSQLCols = []string{"id", "name", "display_name", "created_at", "updated_at"}

// membershipSQLCols are the columns returned by GetUserMemberships.
var membershipSQLCols = []string{
	"organization_id", "organization_name", "role_template_id", "created_at",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

func sampleUserRow() *sqlmock.Rows {
	return sqlmock.NewRows(userSQLCols).
		AddRow("user-1", "alice@example.com", "Alice", nil, time.Now(), time.Now())
}

func emptyUserRows() *sqlmock.Rows {
	return sqlmock.NewRows(userSQLCols)
}

func emptyOrgRows() *sqlmock.Rows {
	return sqlmock.NewRows(orgSQLCols)
}

func emptyMembershipRows() *sqlmock.Rows {
	return sqlmock.NewRows(membershipSQLCols)
}

// newUserRouter creates a gin router with all UserHandlers routes registered.
func newUserRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewUserHandlers(&config.Config{}, db)

	r := gin.New()
	r.GET("/users", h.ListUsersHandler())
	r.GET("/users/search", h.SearchUsersHandler())
	r.GET("/users/me/memberships", h.GetCurrentUserMembershipsHandler())
	r.GET("/users/:id/memberships", h.GetUserMembershipsHandler())
	r.GET("/users/:id", h.GetUserHandler())
	r.POST("/users", h.CreateUserHandler())
	r.PUT("/users/:id", h.UpdateUserHandler())
	r.DELETE("/users/:id", h.DeleteUserHandler())

	return mock, r
}

// withUserID wraps a router to inject user_id into gin context.
func withUserID(r *gin.Engine, userID string) *gin.Engine {
	wrapped := gin.New()
	wrapped.Use(func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Next()
	})
	// Copy routes by embedding the original engine as a handler group
	wrapped.Any("/*path", func(c *gin.Context) {
		r.ServeHTTP(c.Writer, c.Request)
	})
	return wrapped
}

func jsonBody(v interface{}) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

func getJSON(resp *httptest.ResponseRecorder) map[string]interface{} {
	var m map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &m)
	return m
}

// ---------------------------------------------------------------------------
// ListUsersHandler
// ---------------------------------------------------------------------------

func TestListUsersHandler_Success(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT").
		WillReturnRows(sampleUserRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)
	if resp["users"] == nil {
		t.Error("response missing 'users' key")
	}
	if resp["pagination"] == nil {
		t.Error("response missing 'pagination' key")
	}
}

func TestListUsersHandler_DBError(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT COUNT").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestListUsersHandler_PaginationDefaults(t *testing.T) {
	// Bad page/perPage values are clamped to defaults
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT").
		WillReturnRows(emptyUserRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users?page=-1&per_page=9999", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// errDB is a sentinel error for DB failures in tests.
var errDB = &dbError{"database error"}

type dbError struct{ msg string }

func (e *dbError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// GetUserHandler
// ---------------------------------------------------------------------------

func TestGetUserHandler_Success(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnRows(sampleUserRow())
	mock.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnRows(emptyOrgRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/user-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)
	if resp["user"] == nil {
		t.Error("response missing 'user' key")
	}
}

func TestGetUserHandler_NotFound(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("missing").
		WillReturnRows(emptyUserRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/missing", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetUserHandler_DBError(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/user-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateUserHandler
// ---------------------------------------------------------------------------

func TestCreateUserHandler_InvalidJSON(t *testing.T) {
	_, r := newUserRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/users", bytes.NewBufferString("{bad json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateUserHandler_MissingRequiredFields(t *testing.T) {
	_, r := newUserRouter(t)

	// Missing name
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/users",
		jsonBody(map[string]string{"email": "x@example.com"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateUserHandler_MissingEmail(t *testing.T) {
	_, r := newUserRouter(t)

	// Missing email
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/users",
		jsonBody(map[string]string{"name": "Alice"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateUserHandler_Conflict(t *testing.T) {
	mock, r := newUserRouter(t)

	// GetUserByEmail returns existing user
	mock.ExpectQuery("SELECT").WithArgs("alice@example.com").
		WillReturnRows(sampleUserRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/users",
		jsonBody(map[string]string{"email": "alice@example.com", "name": "Alice"})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestCreateUserHandler_Success(t *testing.T) {
	mock, r := newUserRouter(t)

	// GetUserByEmail returns no rows (user doesn't exist)
	mock.ExpectQuery("SELECT").WithArgs("new@example.com").
		WillReturnRows(emptyUserRows())
	// Insert succeeds
	mock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/users",
		jsonBody(map[string]string{"email": "new@example.com", "name": "New User"})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestCreateUserHandler_DBErrorOnCheck(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("err@example.com").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/users",
		jsonBody(map[string]string{"email": "err@example.com", "name": "Err"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// UpdateUserHandler
// ---------------------------------------------------------------------------

func TestUpdateUserHandler_InvalidJSON(t *testing.T) {
	_, r := newUserRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/users/user-1", bytes.NewBufferString("{")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestUpdateUserHandler_NotFound(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("missing").
		WillReturnRows(emptyUserRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/users/missing",
		jsonBody(map[string]string{"name": "New Name"})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUpdateUserHandler_Success(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnRows(sampleUserRow())
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	newName := "Updated Name"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/users/user-1",
		jsonBody(map[string]*string{"name": &newName})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateUserHandler_EmailConflict(t *testing.T) {
	mock, r := newUserRouter(t)

	// GetUserByID returns existing user
	mock.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnRows(sampleUserRow())
	// GetUserByEmail returns a different user (conflict)
	mock.ExpectQuery("SELECT").WithArgs("taken@example.com").
		WillReturnRows(sqlmock.NewRows(userSQLCols).
			AddRow("user-2", "taken@example.com", "Other", nil, time.Now(), time.Now()))

	newEmail := "taken@example.com"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/users/user-1",
		jsonBody(map[string]*string{"email": &newEmail})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteUserHandler
// ---------------------------------------------------------------------------

func TestDeleteUserHandler_NotFound(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("missing").
		WillReturnRows(emptyUserRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/users/missing", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeleteUserHandler_Success(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnRows(sampleUserRow())
	mock.ExpectExec("DELETE FROM users").WithArgs("user-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/users/user-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SearchUsersHandler
// ---------------------------------------------------------------------------

func TestSearchUsersHandler_MissingQuery(t *testing.T) {
	_, r := newUserRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/search", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSearchUsersHandler_Success(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").
		WillReturnRows(sampleUserRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/search?q=alice", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	resp := getJSON(w)
	if resp["users"] == nil {
		t.Error("response missing 'users' key")
	}
}

func TestSearchUsersHandler_DBError(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/search?q=broken", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetCurrentUserMembershipsHandler
// ---------------------------------------------------------------------------

func TestGetCurrentUserMembershipsHandler_Unauthenticated(t *testing.T) {
	_, r := newUserRouter(t)

	// No user_id in context → 401
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/me/memberships", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestGetCurrentUserMembershipsHandler_Success(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnRows(emptyMembershipRows())

	// Inject user_id into gin context via middleware
	auth := gin.New()
	auth.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		c.Next()
	})
	auth.GET("/users/me/memberships", func(c *gin.Context) {
		// Re-route to the underlying handler by serving through the sub-router
		// Since gin doesn't support nested routing elegantly, call handler directly
		r.ServeHTTP(c.Writer, c.Request)
	})

	// Direct approach: set up a router with middleware
	db2, mock2, _ := sqlmock.New()
	defer db2.Close()
	mock2.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnRows(emptyMembershipRows())

	h2 := NewUserHandlers(&config.Config{}, db2)
	r2 := gin.New()
	r2.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		c.Next()
	})
	r2.GET("/users/me/memberships", h2.GetCurrentUserMembershipsHandler())

	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest("GET", "/users/me/memberships", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	_ = mock // suppress unused warning
}

// ---------------------------------------------------------------------------
// GetUserMembershipsHandler
// ---------------------------------------------------------------------------

func TestGetUserMembershipsHandler_UserNotFound(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("missing").
		WillReturnRows(emptyUserRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/missing/memberships", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetUserMembershipsHandler_Success(t *testing.T) {
	mock, r := newUserRouter(t)

	mock.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnRows(sampleUserRow())
	mock.ExpectQuery("SELECT").WithArgs("user-1").
		WillReturnRows(emptyMembershipRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/user-1/memberships", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
