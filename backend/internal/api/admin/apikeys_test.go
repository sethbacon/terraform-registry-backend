package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ---------------------------------------------------------------------------
// Column / row definitions
// ---------------------------------------------------------------------------

var akCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at", "created_at",
}

var akListCols = []string{
	"id", "user_id", "organization_id", "name", "description",
	"key_hash", "key_prefix", "scopes", "expires_at", "last_used_at", "created_at", "user_name",
}

var memberRoleCols = []string{
	"organization_id", "user_id", "role_template_id", "created_at",
	"user_name", "user_email",
	"role_template_name", "role_template_display_name", "role_template_scopes",
}

var testKeyScopes = []byte(`["modules:read"]`)
var testAdminRoleScopes = []byte(`["admin"]`)

func sampleAKRow() *sqlmock.Rows {
	return sqlmock.NewRows(akCols).
		AddRow("key-1", "user-1", "org-1", "CI Key", nil, "hashedkey", "tfr_abc123",
			testKeyScopes, nil, nil, time.Now())
}

func emptyAKRows() *sqlmock.Rows {
	return sqlmock.NewRows(akCols)
}

func sampleAKListRow() *sqlmock.Rows {
	return sqlmock.NewRows(akListCols).
		AddRow("key-1", "user-1", "org-1", "CI Key", nil, "hashedkey", "tfr_abc123",
			testKeyScopes, nil, nil, time.Now(), nil)
}

func sampleMemberRoleRow() *sqlmock.Rows {
	roleTemplateID := "role-1"
	roleName := "admin-role"
	roleDisplay := "Admin Role"
	return sqlmock.NewRows(memberRoleCols).
		AddRow(
			"org-1", "user-1", &roleTemplateID, time.Now(),
			"Alice", "alice@example.com",
			&roleName, &roleDisplay,
			testAdminRoleScopes,
		)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newAPIKeyRouter(t *testing.T, userID string, scopes []string) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewAPIKeyHandlers(&config.Config{}, db)

	r := gin.New()
	if userID != "" {
		uid := userID
		scp := scopes
		r.Use(func(c *gin.Context) {
			c.Set("user_id", uid)
			c.Set("scopes", scp)
			c.Next()
		})
	}
	r.GET("/apikeys", h.ListAPIKeysHandler())
	r.POST("/apikeys", h.CreateAPIKeyHandler())
	r.GET("/apikeys/:id", h.GetAPIKeyHandler())
	r.DELETE("/apikeys/:id", h.DeleteAPIKeyHandler())
	r.PUT("/apikeys/:id", h.UpdateAPIKeyHandler())
	r.POST("/apikeys/:id/rotate", h.RotateAPIKeyHandler())
	return mock, r
}

// ---------------------------------------------------------------------------
// ListAPIKeysHandler
// ---------------------------------------------------------------------------

func TestListAPIKeys_NoAuth(t *testing.T) {
	_, r := newAPIKeyRouter(t, "", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestListAPIKeys_OwnKeys(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("WHERE ak.user_id").
		WillReturnRows(sampleAKListRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["keys"] == nil {
		t.Error("response missing 'keys'")
	}
}

func TestListAPIKeys_AdminListAll(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", []string{"admin"})
	// ListAll has no WHERE, so look for the JOIN directly before ORDER BY
	mock.ExpectQuery("u.id ORDER BY ak.created_at").
		WillReturnRows(sampleAKListRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestListAPIKeys_OrgFilter_NoManageScope(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("WHERE ak.user_id.*AND ak.organization_id").
		WillReturnRows(sampleAKListRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys?organization_id=org-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestListAPIKeys_OrgFilter_WithManageScope(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", []string{"api_keys:manage"})
	mock.ExpectQuery("WHERE ak.organization_id").
		WillReturnRows(sampleAKListRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys?organization_id=org-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestListAPIKeys_DBError(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateAPIKeyHandler
// ---------------------------------------------------------------------------

func TestCreateAPIKey_MissingFields(t *testing.T) {
	_, r := newAPIKeyRouter(t, "user-1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys",
		jsonBody(map[string]interface{}{})))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateAPIKey_NoAuth(t *testing.T) {
	_, r := newAPIKeyRouter(t, "", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys",
		jsonBody(map[string]interface{}{
			"name":            "Test",
			"organization_id": "org-1",
			"scopes":          []string{"modules:read"},
		})))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestCreateAPIKey_Success(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	// GetMemberWithRole
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE").
		WillReturnRows(sampleMemberRoleRow())
	// CreateAPIKey INSERT
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys",
		jsonBody(map[string]interface{}{
			"name":            "My Key",
			"organization_id": "org-1",
			"scopes":          []string{"modules:read"},
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["key"] == nil {
		t.Error("response missing 'key' field")
	}
}

func TestCreateAPIKey_NotMember(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	// GetMemberWithRole returns not found (no rows → nil)
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE").
		WillReturnRows(sqlmock.NewRows(memberRoleCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys",
		jsonBody(map[string]interface{}{
			"name":            "My Key",
			"organization_id": "org-1",
			"scopes":          []string{"modules:read"},
		})))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

func TestCreateAPIKey_InvalidExpiry(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE").
		WillReturnRows(sampleMemberRoleRow())

	badExpiry := "not-a-date"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys",
		jsonBody(map[string]interface{}{
			"name":            "My Key",
			"organization_id": "org-1",
			"scopes":          []string{"modules:read"},
			"expires_at":      badExpiry,
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetAPIKeyHandler
// ---------------------------------------------------------------------------

func TestGetAPIKey_NotFound(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").
		WillReturnRows(emptyAKRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys/key-1", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetAPIKey_OwnKey(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").
		WillReturnRows(sampleAKRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys/key-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestGetAPIKey_OtherUser_NoAdmin(t *testing.T) {
	// context user is "user-2", key belongs to "user-1" → 403
	mock, r := newAPIKeyRouter(t, "user-2", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").
		WillReturnRows(sampleAKRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys/key-1", nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

func TestGetAPIKey_OtherUser_WithAdmin(t *testing.T) {
	// context user is "user-2" with admin scope → allowed
	mock, r := newAPIKeyRouter(t, "user-2", []string{"admin"})
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").
		WillReturnRows(sampleAKRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys/key-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestGetAPIKey_DBError(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys/key-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteAPIKeyHandler
// ---------------------------------------------------------------------------

func TestDeleteAPIKey_NotFound(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(emptyAKRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/apikeys/key-1", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestDeleteAPIKey_Success(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())
	mock.ExpectExec("DELETE FROM api_keys").WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/apikeys/key-1", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteAPIKey_OtherUser_Forbidden(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-2", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/apikeys/key-1", nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteAPIKey_DBError(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())
	mock.ExpectExec("DELETE FROM api_keys").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/apikeys/key-1", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// UpdateAPIKeyHandler
// ---------------------------------------------------------------------------

func TestUpdateAPIKey_NotFound(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(emptyAKRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		jsonBody(map[string]interface{}{"name": "New Name"})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUpdateAPIKey_Success(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())
	mock.ExpectExec("UPDATE api_keys.*SET name").WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		jsonBody(map[string]interface{}{"name": "Updated Key"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateAPIKey_DBError(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())
	mock.ExpectExec("UPDATE api_keys.*SET name").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		jsonBody(map[string]interface{}{"name": "Updated Key"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUpdateAPIKey_Forbidden(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-2", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		jsonBody(map[string]interface{}{"name": "Hacked Name"})))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RotateAPIKeyHandler
// ---------------------------------------------------------------------------

func TestRotateAPIKey_InvalidGracePeriod(t *testing.T) {
	_, r := newAPIKeyRouter(t, "user-1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys/key-1/rotate",
		jsonBody(map[string]interface{}{"grace_period_hours": 100})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRotateAPIKey_NotFound(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(emptyAKRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys/key-1/rotate",
		jsonBody(map[string]interface{}{"grace_period_hours": 0})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRotateAPIKey_ImmediateRevoke(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())
	mock.ExpectExec("INSERT INTO api_keys").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("DELETE FROM api_keys").WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys/key-1/rotate",
		jsonBody(map[string]interface{}{"grace_period_hours": 0})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["new_key"] == nil {
		t.Error("response missing 'new_key'")
	}
}

func TestRotateAPIKey_WithGracePeriod(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())
	mock.ExpectExec("INSERT INTO api_keys").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE api_keys.*SET name").WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys/key-1/rotate",
		jsonBody(map[string]interface{}{"grace_period_hours": 24})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["old_key_status"] != "expires_at" {
		t.Errorf("old_key_status = %v, want 'expires_at'", resp["old_key_status"])
	}
}

func TestRotateAPIKey_Forbidden(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-2", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys/key-1/rotate",
		jsonBody(map[string]interface{}{"grace_period_hours": 0})))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateAPIKeyHandler — additional scope validation paths
// ---------------------------------------------------------------------------

func TestUpdateAPIKey_InvalidScopes(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())

	body := `{"scopes":["invalid:scope"]}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateAPIKey_ScopeExceedsUserRole(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())

	// memberWithRole returns only "modules:read" scope
	roleID := "role-1"
	roleName := "viewer"
	roleDisplay := "Viewer"
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sqlmock.NewRows(memberRoleCols).AddRow(
			"org-1", "user-1", &roleID, time.Now(),
			"Alice", "alice@example.com",
			&roleName, &roleDisplay,
			[]byte(`["modules:read"]`),
		))

	// User tries to give "admin" scope (exceeds their role)
	body := `{"scopes":["modules:read","admin"]}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateAPIKey_WithScopes_GetMemberWithRole_DBError(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnError(errDB)

	body := `{"scopes":["modules:read"]}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateAPIKey_WithValidScopes_AdminRole(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())
	// Admin role - any scope is allowed
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sampleMemberRoleRow())
	mock.ExpectExec("UPDATE api_keys").WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{"scopes":["modules:read","modules:write"]}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateAPIKey_WithExpiresAt(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())
	mock.ExpectExec("UPDATE api_keys").WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{"expires_at":"2030-01-01T00:00:00Z"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateAPIKey_WithInvalidExpiresAt(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())

	body := `{"expires_at":"not-a-date"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}
