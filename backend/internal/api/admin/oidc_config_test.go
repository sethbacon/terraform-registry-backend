package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// oidcConfigCols mirrors the OIDCConfig struct db tags used by sqlx column mapping.
var oidcConfigCols = []string{
	"id", "name", "provider_type", "issuer_url", "client_id", "client_secret_encrypted",
	"redirect_url", "scopes", "is_active", "extra_config",
	"created_at", "updated_at", "created_by", "updated_by",
}

func newOIDCConfigAdminRouter(t *testing.T) (*OIDCConfigAdminHandlers, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	repo := repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock"))
	return NewOIDCConfigAdminHandlers(repo), mock
}

// ---------------------------------------------------------------------------
// NewOIDCConfigAdminHandlers
// ---------------------------------------------------------------------------

func TestNewOIDCConfigAdminHandlers_NotNil(t *testing.T) {
	h, _ := newOIDCConfigAdminRouter(t)
	if h == nil {
		t.Fatal("NewOIDCConfigAdminHandlers returned nil")
	}
}

// ---------------------------------------------------------------------------
// GetActiveOIDCConfig
// ---------------------------------------------------------------------------

func TestGetActiveOIDCConfig_NotFound(t *testing.T) {
	h, mock := newOIDCConfigAdminRouter(t)
	mock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols))

	w := httptest.NewRecorder()
	r := gin.New()
	r.GET("/oidc/config", h.GetActiveOIDCConfig)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/config", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetActiveOIDCConfig_DBError(t *testing.T) {
	h, mock := newOIDCConfigAdminRouter(t)
	mock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r := gin.New()
	r.GET("/oidc/config", h.GetActiveOIDCConfig)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/config", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetActiveOIDCConfig_Success(t *testing.T) {
	h, mock := newOIDCConfigAdminRouter(t)

	id := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).
			AddRow(id, "test", "generic_oidc", "https://issuer.example.com", "client-1", "enc-secret",
				"https://app.example.com/cb", []byte(`["openid","email"]`), true, []byte(`{}`),
				now, now, nil, nil))

	w := httptest.NewRecorder()
	r := gin.New()
	r.GET("/oidc/config", h.GetActiveOIDCConfig)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/config", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["client_id"] != "client-1" {
		t.Errorf("client_id = %v, want client-1", resp["client_id"])
	}
	if _, found := resp["client_secret_encrypted"]; found {
		t.Error("response must not expose client_secret_encrypted")
	}
}

// ---------------------------------------------------------------------------
// UpdateGroupMapping
// ---------------------------------------------------------------------------

func TestUpdateGroupMapping_BadJSON(t *testing.T) {
	h, _ := newOIDCConfigAdminRouter(t)

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/oidc/group-mapping", h.UpdateGroupMapping)
	req := httptest.NewRequest(http.MethodPut, "/oidc/group-mapping", strings.NewReader("{bad json"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestUpdateGroupMapping_NoActiveConfig(t *testing.T) {
	h, mock := newOIDCConfigAdminRouter(t)
	mock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols))

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/oidc/group-mapping", h.UpdateGroupMapping)
	req := httptest.NewRequest(http.MethodPut, "/oidc/group-mapping",
		strings.NewReader(`{"group_claim_name":"groups"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestUpdateGroupMapping_GetConfigDBError(t *testing.T) {
	h, mock := newOIDCConfigAdminRouter(t)
	mock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/oidc/group-mapping", h.UpdateGroupMapping)
	req := httptest.NewRequest(http.MethodPut, "/oidc/group-mapping",
		strings.NewReader(`{"group_claim_name":"groups"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestUpdateGroupMapping_Success(t *testing.T) {
	h, mock := newOIDCConfigAdminRouter(t)

	id := uuid.New()
	now := time.Now()
	baseRow := func() *sqlmock.Rows {
		return sqlmock.NewRows(oidcConfigCols).
			AddRow(id, "test", "generic_oidc", "https://issuer.example.com", "client-1", "enc",
				"https://app.example.com/cb", []byte(`["openid"]`), true, []byte(`{}`), now, now, nil, nil)
	}
	updatedExtra := `{"group_claim_name":"groups","group_mappings":null,"default_role":""}`
	updatedRow := sqlmock.NewRows(oidcConfigCols).
		AddRow(id, "test", "generic_oidc", "https://issuer.example.com", "client-1", "enc",
			"https://app.example.com/cb", []byte(`["openid"]`), true, []byte(updatedExtra), now, now, nil, nil)

	mock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").WillReturnRows(baseRow())
	mock.ExpectExec("UPDATE oidc_config SET extra_config").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").WillReturnRows(updatedRow)

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/oidc/group-mapping", h.UpdateGroupMapping)
	req := httptest.NewRequest(http.MethodPut, "/oidc/group-mapping",
		strings.NewReader(`{"group_claim_name":"groups"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["group_claim_name"] != "groups" {
		t.Errorf("group_claim_name = %v, want groups", resp["group_claim_name"])
	}
}

func TestUpdateGroupMapping_UpdateExecError(t *testing.T) {
	h, mock := newOIDCConfigAdminRouter(t)

	id := uuid.New()
	now := time.Now()
	mock.ExpectQuery("SELECT .* FROM oidc_config WHERE is_active").
		WillReturnRows(sqlmock.NewRows(oidcConfigCols).
			AddRow(id, "test", "generic_oidc", "https://issuer.example.com", "client-1", "enc",
				"https://app.example.com/cb", []byte(`["openid"]`), true, []byte(`{}`), now, now, nil, nil))
	mock.ExpectExec("UPDATE oidc_config SET extra_config").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/oidc/group-mapping", h.UpdateGroupMapping)
	req := httptest.NewRequest(http.MethodPut, "/oidc/group-mapping",
		strings.NewReader(`{"group_claim_name":"groups"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
