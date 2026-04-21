package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/local"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Setenv("TFR_JWT_SECRET", "test-setup-jwt-secret-32chars!!!!!")
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// setupTestEnv creates mocked repos and a setup Handlers instance.
// Returns the handler, sqlmock for oidcConfigRepo, sqlmock for storageConfigRepo,
// sqlmock for userRepo, and sqlmock for orgRepo.
type testEnv struct {
	h           *Handlers
	oidcMock    sqlmock.Sqlmock
	storageMock sqlmock.Sqlmock
	userMock    sqlmock.Sqlmock
	orgMock     sqlmock.Sqlmock
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// OIDC config repo (sqlx)
	oidcDB, oidcMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { oidcDB.Close() })
	oidcRepo := repositories.NewOIDCConfigRepository(sqlx.NewDb(oidcDB, "sqlmock"))

	// Storage config repo (sqlx)
	storageDB, storageMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { storageDB.Close() })
	storageRepo := repositories.NewStorageConfigRepository(sqlx.NewDb(storageDB, "sqlmock"))

	// User repo (database/sql)
	userDB, userMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { userDB.Close() })
	userRepo := repositories.NewUserRepository(userDB)

	// Organization repo (database/sql)
	orgDB, orgMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { orgDB.Close() })
	orgRepo := repositories.NewOrganizationRepository(orgDB)

	// TokenCipher needs a 32-byte key
	cipher, err := crypto.NewTokenCipher([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}

	h := NewHandlers(
		&config.Config{},
		cipher,
		oidcRepo,
		storageRepo,
		userRepo,
		orgRepo,
		nil, // authHandlers — nil is ok; we don't test live OIDC swap here
	)

	return &testEnv{
		h:           h,
		oidcMock:    oidcMock,
		storageMock: storageMock,
		userMock:    userMock,
		orgMock:     orgMock,
	}
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

// allSettingsCols returns the complete list of system_settings columns that
// sqlx will scan from SELECT *. Whenever the SystemSettings struct gains new
// fields, this list must be updated.
func allSettingsCols() []string {
	return []string{
		"id", "storage_configured", "storage_configured_at", "storage_configured_by",
		"setup_completed", "setup_token_hash", "oidc_configured", "pending_admin_email",
		"scanning_configured", "scanning_configured_at", "scanning_config",
		"auth_method", "ldap_configured", "ldap_configured_at", "ldap_config",
		"audit_retention_days", "created_at", "updated_at",
	}
}

// settingsRow creates a sqlmock row matching allSettingsCols().
// Required: storageConfigured, setupCompleted, oidcConfigured, pendingAdminEmail.
// Optional fields default to sensible zero-values.
type settingsOpts struct {
	StorageConfigured  bool
	SetupCompleted     bool
	OIDCConfigured     bool
	LDAPConfigured     bool
	AuthMethod         string
	ScanningConfigured bool
	PendingAdminEmail  interface{} // nil or string
}

func settingsRow(opts settingsOpts) *sqlmock.Rows {
	now := time.Now()
	if opts.AuthMethod == "" {
		opts.AuthMethod = "oidc"
	}
	return sqlmock.NewRows(allSettingsCols()).AddRow(
		1, opts.StorageConfigured, now, nil,
		opts.SetupCompleted, nil, opts.OIDCConfigured, opts.PendingAdminEmail,
		opts.ScanningConfigured, nil, nil,
		opts.AuthMethod, opts.LDAPConfigured, nil, nil,
		30, now, now,
	)
}

// ---------------------------------------------------------------------------
// GetSetupStatus
// ---------------------------------------------------------------------------

func TestGetSetupStatus_Success(t *testing.T) {
	env := newTestEnv(t)

	env.oidcMock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(settingsRow(settingsOpts{
			StorageConfigured: true,
			OIDCConfigured:    true,
			PendingAdminEmail: "admin@example.com",
		}))
	// GetScanningConfigured is called as a separate query
	env.oidcMock.ExpectQuery("SELECT scanning_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_configured"}).AddRow(false))

	r := gin.New()
	r.GET("/status", env.h.GetSetupStatus)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := getJSON(w)
	if body["setup_completed"] != false {
		t.Errorf("setup_completed = %v, want false", body["setup_completed"])
	}
	if body["storage_configured"] != true {
		t.Errorf("storage_configured = %v, want true", body["storage_configured"])
	}
	if body["oidc_configured"] != true {
		t.Errorf("oidc_configured = %v, want true", body["oidc_configured"])
	}
}

func TestGetSetupStatus_Error(t *testing.T) {
	env := newTestEnv(t)
	env.oidcMock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnError(errDB)

	r := gin.New()
	r.GET("/status", env.h.GetSetupStatus)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ValidateToken
// ---------------------------------------------------------------------------

func TestValidateToken_ReturnsOK(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/validate", env.h.ValidateToken)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/validate", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := getJSON(w)
	if body["valid"] != true {
		t.Errorf("valid = %v, want true", body["valid"])
	}
}

// ---------------------------------------------------------------------------
// TestOIDCConfig
// ---------------------------------------------------------------------------

func TestTestOIDCConfig_BadJSON(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/oidc/test", env.h.TestOIDCConfig)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc/test", bytes.NewBufferString("{invalid")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestOIDCConfig_MissingFields(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/oidc/test", env.h.TestOIDCConfig)

	// Missing issuer_url — validation should fail
	body := jsonBody(map[string]string{
		"provider_type": "generic_oidc",
		"client_id":     "test",
		"client_secret": "secret",
		"redirect_url":  "https://app/callback",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestOIDCConfig_InvalidIssuerURL(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/oidc/test", env.h.TestOIDCConfig)

	body := jsonBody(map[string]string{
		"provider_type": "generic_oidc",
		"issuer_url":    "not-a-url",
		"client_id":     "test",
		"client_secret": "secret",
		"redirect_url":  "https://app/callback",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid URL", w.Code)
	}
}

func TestTestOIDCConfig_InvalidProviderType(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/oidc/test", env.h.TestOIDCConfig)

	body := jsonBody(map[string]string{
		"provider_type": "invalid_type",
		"issuer_url":    "https://issuer.example.com",
		"client_id":     "test",
		"client_secret": "secret",
		"redirect_url":  "https://app/callback",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid provider_type", w.Code)
	}
}

func TestTestOIDCConfig_DiscoveryFailure(t *testing.T) {
	env := newTestEnv(t)

	// Start a test server that always returns 404 to simulate an unreachable OIDC issuer.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer ts.Close()

	r := gin.New()
	r.POST("/oidc/test", env.h.TestOIDCConfig)

	// Valid input that passes validation but the issuer discovery will fail.
	body := jsonBody(map[string]string{
		"provider_type": "generic_oidc",
		"issuer_url":    ts.URL,
		"client_id":     "test-client",
		"client_secret": "test-secret",
		"redirect_url":  "https://app/callback",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc/test", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp := getJSON(w)
	if resp["success"] != false {
		t.Errorf("success = %v, want false", resp["success"])
	}
	msg, _ := resp["message"].(string)
	if msg == "" {
		t.Error("expected non-empty failure message")
	}
}

// ---------------------------------------------------------------------------
// SaveOIDCConfig
// ---------------------------------------------------------------------------

func TestSaveOIDCConfig_BadJSON(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/oidc", env.h.SaveOIDCConfig)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc", bytes.NewBufferString("not json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSaveOIDCConfig_MissingFields(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/oidc", env.h.SaveOIDCConfig)

	body := jsonBody(map[string]string{
		"provider_type": "generic_oidc",
		"issuer_url":    "https://issuer.example.com",
		// missing client_id, client_secret, redirect_url
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSaveOIDCConfig_DeactivateError(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/oidc", env.h.SaveOIDCConfig)

	body := jsonBody(map[string]string{
		"provider_type": "generic_oidc",
		"issuer_url":    "https://issuer.example.com",
		"client_id":     "test-client",
		"client_secret": "test-secret",
		"redirect_url":  "https://app/callback",
	})

	// Deactivate all fails
	env.oidcMock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc", body))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestSaveOIDCConfig_CreateError(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/oidc", env.h.SaveOIDCConfig)

	body := jsonBody(map[string]string{
		"provider_type": "generic_oidc",
		"issuer_url":    "https://issuer.example.com",
		"client_id":     "test-client",
		"client_secret": "test-secret",
		"redirect_url":  "https://app/callback",
	})

	env.oidcMock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 0))
	env.oidcMock.ExpectExec("INSERT INTO oidc_config").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc", body))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestSaveOIDCConfig_Success(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/oidc", env.h.SaveOIDCConfig)

	body := jsonBody(map[string]string{
		"provider_type": "generic_oidc",
		"issuer_url":    "https://issuer.example.com",
		"client_id":     "test-client",
		"client_secret": "test-secret",
		"redirect_url":  "https://app/callback",
	})

	// Deactivate existing configs
	env.oidcMock.ExpectExec("UPDATE oidc_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Create new config
	env.oidcMock.ExpectExec("INSERT INTO oidc_config").
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Mark OIDC as configured
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/oidc", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp := getJSON(w)
	if resp["provider_type"] != "generic_oidc" {
		t.Errorf("provider_type = %v", resp["provider_type"])
	}
	if resp["issuer_url"] != "https://issuer.example.com" {
		t.Errorf("issuer_url = %v", resp["issuer_url"])
	}
}

// ---------------------------------------------------------------------------
// TestStorageConfig
// ---------------------------------------------------------------------------

func TestTestStorageConfig_BadJSON(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/storage/test", env.h.TestStorageConfig)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/test", bytes.NewBufferString("{bad")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestStorageConfig_LocalSuccess(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/storage/test", env.h.TestStorageConfig)

	body := jsonBody(map[string]interface{}{
		"backend_type":    "local",
		"local_base_path": t.TempDir(),
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/test", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp := getJSON(w)
	if resp["success"] != true {
		t.Errorf("success = %v, want true, body: %s", resp["success"], w.Body.String())
	}
}

func TestTestStorageConfig_InitFailure(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/storage/test", env.h.TestStorageConfig)

	// Create a regular file to block os.MkdirAll from creating a directory under it.
	blockFile := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blockFile, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(blockFile, "sub", "dir")

	body := jsonBody(map[string]interface{}{
		"backend_type":    "local",
		"local_base_path": badPath,
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/test", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp := getJSON(w)
	if resp["success"] != false {
		t.Errorf("success = %v, want false", resp["success"])
	}
}

// ---------------------------------------------------------------------------
// SaveStorageConfig
// ---------------------------------------------------------------------------

func TestSaveStorageConfig_BadJSON(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/storage", env.h.SaveStorageConfig)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage", bytes.NewBufferString("nope")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSaveStorageConfig_LocalSuccess(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/storage", env.h.SaveStorageConfig)

	body := jsonBody(map[string]interface{}{
		"backend_type":    "local",
		"local_base_path": t.TempDir(),
	})

	// Deactivate existing
	env.storageMock.ExpectExec("UPDATE storage_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Create
	env.storageMock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Mark storage as configured
	env.storageMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage", body))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
}

func TestSaveStorageConfig_CreateError(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/storage", env.h.SaveStorageConfig)

	body := jsonBody(map[string]interface{}{
		"backend_type":    "local",
		"local_base_path": "/tmp/test",
	})

	env.storageMock.ExpectExec("UPDATE storage_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(0, 0))
	env.storageMock.ExpectExec("INSERT INTO storage_config").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage", body))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ConfigureAdmin
// ---------------------------------------------------------------------------

func TestConfigureAdmin_BadJSON(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", bytes.NewBufferString("bad")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestConfigureAdmin_InvalidEmail(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	body := jsonBody(map[string]string{"email": "not-an-email"})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestConfigureAdmin_OrgNotFound(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	body := jsonBody(map[string]string{"email": "admin@example.com"})

	// GetDefaultOrganization returns nil (not found)
	env.orgMock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", body))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestConfigureAdmin_Success(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	body := jsonBody(map[string]string{"email": "admin@example.com"})

	now := time.Now()
	orgCols := []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
	env.orgMock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(orgCols).AddRow("org-1", "default", "Default Org", nil, nil, now, now))

	// CreateUser
	env.userMock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// AddMemberWithParams — looks up role_template by name first
	env.orgMock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-admin-id"))
	env.orgMock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// SetPendingAdminEmail
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp := getJSON(w)
	if resp["email"] != "admin@example.com" {
		t.Errorf("email = %v, want admin@example.com", resp["email"])
	}
}

func TestConfigureAdmin_ExistingUserFallback(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	body := jsonBody(map[string]string{"email": "admin@example.com"})

	now := time.Now()
	orgCols := []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
	env.orgMock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(orgCols).AddRow("org-1", "default", "Default Org", nil, nil, now, now))

	// CreateUser fails (e.g. duplicate key)
	env.userMock.ExpectExec("INSERT INTO users").
		WillReturnError(errDB)

	// GetUserByEmail returns the existing user
	userCols := []string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}
	env.userMock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("admin@example.com").
		WillReturnRows(sqlmock.NewRows(userCols).AddRow(
			"existing-user-id", "admin@example.com", "admin@example.com", nil, now, now,
		))

	// AddMemberWithParams
	env.orgMock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-admin-id"))
	env.orgMock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// SetPendingAdminEmail
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp2 := getJSON(w)
	if resp2["email"] != "admin@example.com" {
		t.Errorf("email = %v, want admin@example.com", resp2["email"])
	}
}

func TestConfigureAdmin_CreateAndFindBothFail(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	body := jsonBody(map[string]string{"email": "admin@example.com"})

	now := time.Now()
	orgCols := []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
	env.orgMock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(orgCols).AddRow("org-1", "default", "Default Org", nil, nil, now, now))

	// CreateUser fails
	env.userMock.ExpectExec("INSERT INTO users").
		WillReturnError(errDB)

	// GetUserByEmail also fails
	env.userMock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("admin@example.com").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", body))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestConfigureAdmin_AddMemberFails_UpdateRoleSucceeds(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	body := jsonBody(map[string]string{"email": "admin@example.com"})

	now := time.Now()
	orgCols := []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
	env.orgMock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(orgCols).AddRow("org-1", "default", "Default Org", nil, nil, now, now))

	// CreateUser succeeds
	env.userMock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// AddMemberWithParams: role template lookup succeeds but INSERT fails
	env.orgMock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-admin-id"))
	env.orgMock.ExpectExec("INSERT INTO organization_members").
		WillReturnError(errDB)

	// UpdateMemberRole: role template lookup succeeds and UPDATE succeeds
	env.orgMock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-admin-id"))
	env.orgMock.ExpectExec("UPDATE organization_members").
		WillReturnResult(sqlmock.NewResult(0, 1))

	// SetPendingAdminEmail
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp2 := getJSON(w)
	if resp2["email"] != "admin@example.com" {
		t.Errorf("email = %v, want admin@example.com", resp2["email"])
	}
}

func TestConfigureAdmin_AddMemberFails_UpdateRoleFails(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	body := jsonBody(map[string]string{"email": "admin@example.com"})

	now := time.Now()
	orgCols := []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
	env.orgMock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(orgCols).AddRow("org-1", "default", "Default Org", nil, nil, now, now))

	// CreateUser succeeds
	env.userMock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// AddMemberWithParams: role template lookup succeeds but INSERT fails
	env.orgMock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-admin-id"))
	env.orgMock.ExpectExec("INSERT INTO organization_members").
		WillReturnError(errDB)

	// UpdateMemberRole: role template lookup fails
	env.orgMock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", body))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestConfigureAdmin_PendingAdminEmailFails(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/admin", env.h.ConfigureAdmin)

	body := jsonBody(map[string]string{"email": "admin@example.com"})

	now := time.Now()
	orgCols := []string{"id", "name", "display_name", "idp_type", "idp_name", "created_at", "updated_at"}
	env.orgMock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows(orgCols).AddRow("org-1", "default", "Default Org", nil, nil, now, now))

	// CreateUser succeeds
	env.userMock.ExpectExec("INSERT INTO users").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// AddMemberWithParams succeeds
	env.orgMock.ExpectQuery("SELECT id FROM role_templates WHERE name").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-admin-id"))
	env.orgMock.ExpectExec("INSERT INTO organization_members").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// SetPendingAdminEmail fails (non-fatal)
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/admin", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (non-fatal error), body: %s", w.Code, w.Body.String())
	}

	resp2 := getJSON(w)
	if resp2["email"] != "admin@example.com" {
		t.Errorf("email = %v, want admin@example.com", resp2["email"])
	}
}

// ---------------------------------------------------------------------------
// CompleteSetup
// ---------------------------------------------------------------------------

func TestCompleteSetup_StatusError(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/complete", env.h.CompleteSetup)

	env.oidcMock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/complete", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestCompleteSetup_Incomplete(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/complete", env.h.CompleteSetup)

	// OIDC not configured, storage not configured, no admin
	env.oidcMock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(settingsRow(settingsOpts{}))
	env.oidcMock.ExpectQuery("SELECT scanning_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_configured"}).AddRow(false))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/complete", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}

	resp := getJSON(w)
	missing, ok := resp["missing"].([]interface{})
	if !ok || len(missing) != 3 {
		t.Errorf("expected 3 missing items, got %v", resp["missing"])
	}
}

func TestCompleteSetup_Success(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/complete", env.h.CompleteSetup)

	// All configured
	env.oidcMock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(settingsRow(settingsOpts{
			StorageConfigured: true,
			OIDCConfigured:    true,
			PendingAdminEmail: "admin@example.com",
		}))
	env.oidcMock.ExpectQuery("SELECT scanning_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_configured"}).AddRow(false))
	// SetSetupCompleted
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/complete", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp := getJSON(w)
	if resp["setup_completed"] != true {
		t.Errorf("setup_completed = %v, want true", resp["setup_completed"])
	}
}

func TestCompleteSetup_SetCompletedError(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/complete", env.h.CompleteSetup)

	env.oidcMock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(settingsRow(settingsOpts{
			StorageConfigured: true,
			OIDCConfigured:    true,
			PendingAdminEmail: "admin@example.com",
		}))
	env.oidcMock.ExpectQuery("SELECT scanning_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_configured"}).AddRow(false))
	// SetSetupCompleted fails
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/complete", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// validateOIDCInput
// ---------------------------------------------------------------------------

func TestValidateOIDCInput_AllValid(t *testing.T) {
	input := &models.OIDCConfigInput{
		ProviderType: "generic_oidc",
		IssuerURL:    "https://example.com",
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURL:  "https://app/callback",
	}
	if err := validateOIDCInput(input); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateOIDCInput_EmptyIssuerURL(t *testing.T) {
	input := &models.OIDCConfigInput{
		ClientID:     "c",
		ClientSecret: "s",
		RedirectURL:  "https://app/callback",
	}
	if err := validateOIDCInput(input); err == nil {
		t.Error("expected error for empty issuer_url")
	}
}

func TestValidateOIDCInput_BadIssuerURL(t *testing.T) {
	input := &models.OIDCConfigInput{
		IssuerURL:    "ftp://bad-scheme",
		ClientID:     "c",
		ClientSecret: "s",
		RedirectURL:  "https://app/callback",
	}
	if err := validateOIDCInput(input); err == nil {
		t.Error("expected error for non-http(s) issuer_url")
	}
}

func TestValidateOIDCInput_EmptyClientID(t *testing.T) {
	input := &models.OIDCConfigInput{
		IssuerURL:    "https://example.com",
		ClientSecret: "s",
		RedirectURL:  "https://app/callback",
	}
	if err := validateOIDCInput(input); err == nil {
		t.Error("expected error for empty client_id")
	}
}

func TestValidateOIDCInput_EmptyClientSecret(t *testing.T) {
	input := &models.OIDCConfigInput{
		IssuerURL:   "https://example.com",
		ClientID:    "c",
		RedirectURL: "https://app/callback",
	}
	if err := validateOIDCInput(input); err == nil {
		t.Error("expected error for empty client_secret")
	}
}

func TestValidateOIDCInput_EmptyRedirectURL(t *testing.T) {
	input := &models.OIDCConfigInput{
		IssuerURL:    "https://example.com",
		ClientID:     "c",
		ClientSecret: "s",
	}
	if err := validateOIDCInput(input); err == nil {
		t.Error("expected error for empty redirect_url")
	}
}

func TestValidateOIDCInput_DefaultsProviderType(t *testing.T) {
	input := &models.OIDCConfigInput{
		IssuerURL:    "https://example.com",
		ClientID:     "c",
		ClientSecret: "s",
		RedirectURL:  "https://app/callback",
	}
	if err := validateOIDCInput(input); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if input.ProviderType != "generic_oidc" {
		t.Errorf("ProviderType = %q, want generic_oidc", input.ProviderType)
	}
}

func TestValidateOIDCInput_InvalidProviderType(t *testing.T) {
	input := &models.OIDCConfigInput{
		ProviderType: "saml",
		IssuerURL:    "https://example.com",
		ClientID:     "c",
		ClientSecret: "s",
		RedirectURL:  "https://app/callback",
	}
	if err := validateOIDCInput(input); err == nil {
		t.Error("expected error for invalid provider_type")
	}
}

// ---------------------------------------------------------------------------
// toNullString
// ---------------------------------------------------------------------------

func TestToNullString_Empty(t *testing.T) {
	ns := toNullString("")
	if ns.Valid {
		t.Error("expected Valid=false for empty string")
	}
}

func TestToNullString_NonEmpty(t *testing.T) {
	ns := toNullString("hello")
	if !ns.Valid {
		t.Error("expected Valid=true")
	}
	if ns.String != "hello" {
		t.Errorf("String = %q, want hello", ns.String)
	}
}

// ---------------------------------------------------------------------------
// buildTestStorageConfig
// ---------------------------------------------------------------------------

func TestBuildTestStorageConfig_Local(t *testing.T) {
	input := &models.StorageConfigInput{
		BackendType:   "local",
		LocalBasePath: "/tmp/test",
	}
	cfg := buildTestStorageConfig(input)
	if cfg.Storage.DefaultBackend != "local" {
		t.Errorf("DefaultBackend = %q, want local", cfg.Storage.DefaultBackend)
	}
	if cfg.Storage.Local.BasePath != "/tmp/test" {
		t.Errorf("BasePath = %q", cfg.Storage.Local.BasePath)
	}
}

func TestBuildTestStorageConfig_Azure(t *testing.T) {
	input := &models.StorageConfigInput{
		BackendType:        "azure",
		AzureAccountName:   "myaccount",
		AzureAccountKey:    "mykey",
		AzureContainerName: "mycontainer",
	}
	cfg := buildTestStorageConfig(input)
	if cfg.Storage.DefaultBackend != "azure" {
		t.Errorf("DefaultBackend = %q, want azure", cfg.Storage.DefaultBackend)
	}
	if cfg.Storage.Azure.AccountName != "myaccount" {
		t.Errorf("AccountName = %q", cfg.Storage.Azure.AccountName)
	}
}

func TestBuildTestStorageConfig_S3(t *testing.T) {
	input := &models.StorageConfigInput{
		BackendType: "s3",
		S3Bucket:    "my-bucket",
		S3Region:    "us-east-1",
	}
	cfg := buildTestStorageConfig(input)
	if cfg.Storage.S3.Bucket != "my-bucket" {
		t.Errorf("Bucket = %q", cfg.Storage.S3.Bucket)
	}
}

func TestBuildTestStorageConfig_GCS(t *testing.T) {
	input := &models.StorageConfigInput{
		BackendType:  "gcs",
		GCSBucket:    "my-gcs-bucket",
		GCSProjectID: "my-project",
	}
	cfg := buildTestStorageConfig(input)
	if cfg.Storage.GCS.Bucket != "my-gcs-bucket" {
		t.Errorf("Bucket = %q", cfg.Storage.GCS.Bucket)
	}
}

// ---------------------------------------------------------------------------
// buildEncryptedStorageConfig
// ---------------------------------------------------------------------------

func TestBuildEncryptedStorageConfig_Local(t *testing.T) {
	env := newTestEnv(t)

	serveDirectly := true
	input := &models.StorageConfigInput{
		BackendType:        "local",
		LocalBasePath:      "/data/modules",
		LocalServeDirectly: &serveDirectly,
	}

	cfg, err := env.h.buildEncryptedStorageConfig(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BackendType != "local" {
		t.Errorf("BackendType = %q, want local", cfg.BackendType)
	}
	if !cfg.LocalBasePath.Valid || cfg.LocalBasePath.String != "/data/modules" {
		t.Errorf("LocalBasePath = %v", cfg.LocalBasePath)
	}
	if !cfg.LocalServeDirectly.Valid || !cfg.LocalServeDirectly.Bool {
		t.Error("LocalServeDirectly should be true")
	}
}

func TestBuildEncryptedStorageConfig_Azure(t *testing.T) {
	env := newTestEnv(t)

	input := &models.StorageConfigInput{
		BackendType:        "azure",
		AzureAccountName:   "myaccount",
		AzureAccountKey:    "mykey",
		AzureContainerName: "mycontainer",
	}

	cfg, err := env.h.buildEncryptedStorageConfig(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.AzureAccountKeyEncrypted.Valid {
		t.Error("AzureAccountKeyEncrypted should be set")
	}
	if cfg.AzureAccountKeyEncrypted.String == "mykey" {
		t.Error("key should be encrypted, not plain text")
	}
}

func TestBuildEncryptedStorageConfig_S3(t *testing.T) {
	env := newTestEnv(t)

	input := &models.StorageConfigInput{
		BackendType:       "s3",
		S3Bucket:          "bucket",
		S3Region:          "us-east-1",
		S3AccessKeyID:     "AKID",
		S3SecretAccessKey: "secret",
	}

	cfg, err := env.h.buildEncryptedStorageConfig(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.S3AccessKeyIDEncrypted.Valid {
		t.Error("S3AccessKeyIDEncrypted should be set")
	}
	if !cfg.S3SecretAccessKeyEncrypted.Valid {
		t.Error("S3SecretAccessKeyEncrypted should be set")
	}
}

func TestBuildEncryptedStorageConfig_GCS(t *testing.T) {
	env := newTestEnv(t)

	input := &models.StorageConfigInput{
		BackendType:        "gcs",
		GCSBucket:          "bucket",
		GCSProjectID:       "project",
		GCSCredentialsJSON: `{"type":"service_account"}`,
	}

	cfg, err := env.h.buildEncryptedStorageConfig(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.GCSCredentialsJSONEncrypted.Valid {
		t.Error("GCSCredentialsJSONEncrypted should be set")
	}
}

// ---------------------------------------------------------------------------
// TestLDAPConfig
// ---------------------------------------------------------------------------

func TestTestLDAPConfig_BadJSON(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap/test", env.h.TestLDAPConfig)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap/test", bytes.NewBufferString("{invalid")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestLDAPConfig_MissingHost(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap/test", env.h.TestLDAPConfig)

	body := jsonBody(models.LDAPConfigInput{
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestLDAPConfig_MissingBindDN(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap/test", env.h.TestLDAPConfig)

	body := jsonBody(models.LDAPConfigInput{
		Host:         "ldap.example.com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestLDAPConfig_MissingBindPassword(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap/test", env.h.TestLDAPConfig)

	body := jsonBody(models.LDAPConfigInput{
		Host:       "ldap.example.com",
		BindDN:     "cn=admin,dc=example,dc=com",
		BaseDN:     "dc=example,dc=com",
		UserFilter: "(uid=%s)",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestLDAPConfig_MissingBaseDN(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap/test", env.h.TestLDAPConfig)

	body := jsonBody(models.LDAPConfigInput{
		Host:         "ldap.example.com",
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		UserFilter:   "(uid=%s)",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestLDAPConfig_MissingUserFilter(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap/test", env.h.TestLDAPConfig)

	body := jsonBody(models.LDAPConfigInput{
		Host:         "ldap.example.com",
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestLDAPConfig_InvalidPort(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap/test", env.h.TestLDAPConfig)

	body := jsonBody(models.LDAPConfigInput{
		Host:         "ldap.example.com",
		Port:         99999,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap/test", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SaveLDAPConfig
// ---------------------------------------------------------------------------

func TestSaveLDAPConfig_BadJSON(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap", env.h.SaveLDAPConfig)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap", bytes.NewBufferString("{invalid")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSaveLDAPConfig_ValidationError(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap", env.h.SaveLDAPConfig)

	// Missing required host
	body := jsonBody(models.LDAPConfigInput{
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap", body))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSaveLDAPConfig_Success(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap", env.h.SaveLDAPConfig)

	// SetLDAPConfig
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))
	// SetOIDCConfigured (marks auth as configured)
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	body := jsonBody(models.LDAPConfigInput{
		Host:         "ldap.example.com",
		Port:         389,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp := getJSON(w)
	if resp["host"] != "ldap.example.com" {
		t.Errorf("host = %v, want ldap.example.com", resp["host"])
	}
}

func TestSaveLDAPConfig_DBError(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/ldap", env.h.SaveLDAPConfig)

	// SetLDAPConfig fails
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnError(errDB)

	body := jsonBody(models.LDAPConfigInput{
		Host:         "ldap.example.com",
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/ldap", body))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CompleteSetup — LDAP variant
// ---------------------------------------------------------------------------

func TestCompleteSetup_LDAPSuccess(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/complete", env.h.CompleteSetup)

	// LDAP configured instead of OIDC
	env.oidcMock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(settingsRow(settingsOpts{
			StorageConfigured: true,
			LDAPConfigured:    true,
			AuthMethod:        "ldap",
			PendingAdminEmail: "admin@example.com",
		}))
	env.oidcMock.ExpectQuery("SELECT scanning_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_configured"}).AddRow(false))
	// SetSetupCompleted
	env.oidcMock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/complete", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}

	resp := getJSON(w)
	if resp["setup_completed"] != true {
		t.Errorf("setup_completed = %v, want true", resp["setup_completed"])
	}
	// Message should mention LDAP
	msg, _ := resp["message"].(string)
	if msg == "" || !contains(msg, "LDAP") {
		t.Errorf("message should mention LDAP, got: %q", msg)
	}
}

func TestCompleteSetup_NoAuth(t *testing.T) {
	env := newTestEnv(t)

	r := gin.New()
	r.POST("/complete", env.h.CompleteSetup)

	// Neither OIDC nor LDAP configured, but storage + admin are
	env.oidcMock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(settingsRow(settingsOpts{
			StorageConfigured: true,
			PendingAdminEmail: "admin@example.com",
		}))
	env.oidcMock.ExpectQuery("SELECT scanning_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_configured"}).AddRow(false))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/complete", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}

	resp := getJSON(w)
	missing, ok := resp["missing"].([]interface{})
	if !ok || len(missing) != 1 {
		t.Errorf("expected 1 missing item (auth), got %v", resp["missing"])
	}
}

// ---------------------------------------------------------------------------
// GetSetupStatus — LDAP fields
// ---------------------------------------------------------------------------

func TestGetSetupStatus_LDAPConfigured(t *testing.T) {
	env := newTestEnv(t)

	env.oidcMock.ExpectQuery("SELECT.*FROM system_settings").
		WillReturnRows(settingsRow(settingsOpts{
			StorageConfigured: true,
			LDAPConfigured:    true,
			AuthMethod:        "ldap",
			PendingAdminEmail: "admin@example.com",
		}))
	env.oidcMock.ExpectQuery("SELECT scanning_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"scanning_configured"}).AddRow(false))

	r := gin.New()
	r.GET("/status", env.h.GetSetupStatus)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := getJSON(w)
	if body["ldap_configured"] != true {
		t.Errorf("ldap_configured = %v, want true", body["ldap_configured"])
	}
	if body["auth_method"] != "ldap" {
		t.Errorf("auth_method = %v, want ldap", body["auth_method"])
	}
}

// ---------------------------------------------------------------------------
// validateLDAPInput
// ---------------------------------------------------------------------------

func TestValidateLDAPInput_AllValid(t *testing.T) {
	input := &models.LDAPConfigInput{
		Host:         "ldap.example.com",
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	}
	if err := validateLDAPInput(input); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateLDAPInput_EmptyHost(t *testing.T) {
	input := &models.LDAPConfigInput{
		BindDN: "cn=admin", BindPassword: "s", BaseDN: "dc=x", UserFilter: "(uid=%s)",
	}
	if err := validateLDAPInput(input); err == nil {
		t.Error("expected error for empty host")
	}
}

func TestValidateLDAPInput_EmptyBindDN(t *testing.T) {
	input := &models.LDAPConfigInput{
		Host: "ldap", BindPassword: "s", BaseDN: "dc=x", UserFilter: "(uid=%s)",
	}
	if err := validateLDAPInput(input); err == nil {
		t.Error("expected error for empty bind_dn")
	}
}

func TestValidateLDAPInput_EmptyBindPassword(t *testing.T) {
	input := &models.LDAPConfigInput{
		Host: "ldap", BindDN: "cn=admin", BaseDN: "dc=x", UserFilter: "(uid=%s)",
	}
	if err := validateLDAPInput(input); err == nil {
		t.Error("expected error for empty bind_password")
	}
}

func TestValidateLDAPInput_EmptyBaseDN(t *testing.T) {
	input := &models.LDAPConfigInput{
		Host: "ldap", BindDN: "cn=admin", BindPassword: "s", UserFilter: "(uid=%s)",
	}
	if err := validateLDAPInput(input); err == nil {
		t.Error("expected error for empty base_dn")
	}
}

func TestValidateLDAPInput_EmptyUserFilter(t *testing.T) {
	input := &models.LDAPConfigInput{
		Host: "ldap", BindDN: "cn=admin", BindPassword: "s", BaseDN: "dc=x",
	}
	if err := validateLDAPInput(input); err == nil {
		t.Error("expected error for empty user_filter")
	}
}

func TestValidateLDAPInput_InvalidPort(t *testing.T) {
	input := &models.LDAPConfigInput{
		Host: "ldap", Port: 99999, BindDN: "cn=admin", BindPassword: "s",
		BaseDN: "dc=x", UserFilter: "(uid=%s)",
	}
	if err := validateLDAPInput(input); err == nil {
		t.Error("expected error for invalid port")
	}
}

// ---------------------------------------------------------------------------
// ldapInputToConfig
// ---------------------------------------------------------------------------

func TestLdapInputToConfig_Defaults(t *testing.T) {
	input := &models.LDAPConfigInput{
		Host:         "ldap.example.com",
		BindDN:       "cn=admin",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	}

	cfg := ldapInputToConfig(input)

	if cfg.Port != 389 {
		t.Errorf("Port = %d, want 389", cfg.Port)
	}
	if cfg.UserAttrEmail != "mail" {
		t.Errorf("UserAttrEmail = %q, want mail", cfg.UserAttrEmail)
	}
	if cfg.UserAttrName != "displayName" {
		t.Errorf("UserAttrName = %q, want displayName", cfg.UserAttrName)
	}
	if cfg.GroupMemberAttr != "member" {
		t.Errorf("GroupMemberAttr = %q, want member", cfg.GroupMemberAttr)
	}
	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
}

func TestLdapInputToConfig_TLSPort(t *testing.T) {
	input := &models.LDAPConfigInput{
		Host:         "ldap.example.com",
		UseTLS:       true,
		BindDN:       "cn=admin",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	}

	cfg := ldapInputToConfig(input)

	if cfg.Port != 636 {
		t.Errorf("Port = %d, want 636 for TLS", cfg.Port)
	}
}

func TestLdapInputToConfig_CustomValues(t *testing.T) {
	input := &models.LDAPConfigInput{
		Host:            "ldap.example.com",
		Port:            3269,
		BindDN:          "cn=admin",
		BindPassword:    "secret",
		BaseDN:          "dc=example,dc=com",
		UserFilter:      "(sAMAccountName=%s)",
		UserAttrEmail:   "userPrincipalName",
		UserAttrName:    "cn",
		GroupMemberAttr: "uniqueMember",
	}

	cfg := ldapInputToConfig(input)

	if cfg.Port != 3269 {
		t.Errorf("Port = %d, want 3269", cfg.Port)
	}
	if cfg.UserAttrEmail != "userPrincipalName" {
		t.Errorf("UserAttrEmail = %q, want userPrincipalName", cfg.UserAttrEmail)
	}
	if cfg.UserAttrName != "cn" {
		t.Errorf("UserAttrName = %q, want cn", cfg.UserAttrName)
	}
	if cfg.GroupMemberAttr != "uniqueMember" {
		t.Errorf("GroupMemberAttr = %q, want uniqueMember", cfg.GroupMemberAttr)
	}
}

// ---------------------------------------------------------------------------
// helpers & sentinel
// ---------------------------------------------------------------------------

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstring(s, sub))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var errDB = errors.New("database error")
