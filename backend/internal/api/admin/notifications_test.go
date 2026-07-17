package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// testTokenCipher is defined in scm_providers_test.go (shared helper).

// newNotificationsHandler builds a NotificationsHandler backed by sqlmock, mirroring
// the newOIDCConfigAdminRouter pattern used elsewhere in this package.
func newNotificationsHandler(t *testing.T) (*NotificationsHandler, *config.NotificationsConfig, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	repo := repositories.NewOIDCConfigRepository(sqlx.NewDb(db, "sqlmock"))
	cfg := &config.NotificationsConfig{}
	cveCfg := &config.CVEConfig{}
	return NewNotificationsHandler(cfg, repo, testTokenCipher(t), cveCfg), cfg, mock
}

// ---------------------------------------------------------------------------
// validateNotificationsInput (pure)
// ---------------------------------------------------------------------------

func TestValidateNotificationsInput_DisabledNoFieldsRequired(t *testing.T) {
	input := &notificationsConfigInput{Enabled: false}
	input.SMTP.Port = 587

	if err := validateNotificationsInput(input); err != nil {
		t.Errorf("expected no error when disabled, got %v", err)
	}
}

func TestValidateNotificationsInput_EnabledRequiresHostAndFrom(t *testing.T) {
	input := &notificationsConfigInput{Enabled: true}
	input.SMTP.Port = 587
	if err := validateNotificationsInput(input); err == nil {
		t.Fatal("expected error when enabled without host/from")
	}

	input.SMTP.Host = "smtp.example.com"
	if err := validateNotificationsInput(input); err == nil {
		t.Fatal("expected error when enabled without from")
	}

	input.SMTP.From = "not-an-email"
	if err := validateNotificationsInput(input); err == nil {
		t.Fatal("expected error for invalid from address")
	}

	input.SMTP.From = "admin@example.com"
	if err := validateNotificationsInput(input); err != nil {
		t.Errorf("expected no error with valid host/from, got %v", err)
	}
}

func TestValidateNotificationsInput_PortRange(t *testing.T) {
	input := &notificationsConfigInput{}
	input.SMTP.Port = 0
	if err := validateNotificationsInput(input); err == nil {
		t.Fatal("expected error for port 0 (caller must default before validating)")
	}

	input.SMTP.Port = 70000
	if err := validateNotificationsInput(input); err == nil {
		t.Fatal("expected error for out-of-range port")
	}

	input.SMTP.Port = 587
	if err := validateNotificationsInput(input); err != nil {
		t.Errorf("expected no error for valid port, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// buildNotificationsConfigDB (pure, seal + empty-password-preserves rule)
// ---------------------------------------------------------------------------

func TestBuildNotificationsConfigDB_SealsNewPassword(t *testing.T) {
	tc := testTokenCipher(t)
	input := notificationsConfigInput{Enabled: true}
	input.SMTP.Host = "smtp.example.com"
	input.SMTP.From = "admin@example.com"
	input.SMTP.Password = "hunter2"

	dbc, err := buildNotificationsConfigDB(input, tc, "existing-ciphertext")
	if err != nil {
		t.Fatalf("buildNotificationsConfigDB: %v", err)
	}
	if dbc.SMTP.PasswordEncrypted == "" || dbc.SMTP.PasswordEncrypted == "existing-ciphertext" {
		t.Fatalf("expected a newly sealed ciphertext, got %q", dbc.SMTP.PasswordEncrypted)
	}

	decrypted, err := tc.Open(dbc.SMTP.PasswordEncrypted)
	if err != nil {
		t.Fatalf("tc.Open: %v", err)
	}
	if decrypted != "hunter2" {
		t.Errorf("decrypted password = %q, want %q", decrypted, "hunter2")
	}
}

func TestBuildNotificationsConfigDB_EmptyPasswordPreservesExisting(t *testing.T) {
	tc := testTokenCipher(t)
	input := notificationsConfigInput{Enabled: true}
	input.SMTP.Host = "smtp.example.com"
	input.SMTP.From = "admin@example.com"
	// Password intentionally left empty.

	dbc, err := buildNotificationsConfigDB(input, tc, "existing-ciphertext")
	if err != nil {
		t.Fatalf("buildNotificationsConfigDB: %v", err)
	}
	if dbc.SMTP.PasswordEncrypted != "existing-ciphertext" {
		t.Errorf("PasswordEncrypted = %q, want preserved %q", dbc.SMTP.PasswordEncrypted, "existing-ciphertext")
	}
}

// ---------------------------------------------------------------------------
// GetConfig (handler, sqlmock-backed)
// ---------------------------------------------------------------------------

func TestNotificationsHandler_GetConfig_NoPassword(t *testing.T) {
	h, _, mock := newNotificationsHandler(t)
	mock.ExpectQuery("SELECT notifications_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow(nil))

	w := httptest.NewRecorder()
	r := gin.New()
	r.GET("/notifications/config", h.GetConfig)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/notifications/config", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp NotificationsConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.PasswordConfigured {
		t.Error("expected password_configured=false")
	}
	// The password_configured key must be present, but the raw password / ciphertext must not be.
	if !strings.Contains(w.Body.String(), "password_configured") {
		t.Error("response should include the password_configured field")
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "smtp_password_encrypted") {
		t.Error("response must never include the encrypted password field")
	}
}

// TestNotificationsHandler_GetConfig_RecipientsNeverNull guards against a
// regression that crashed the admin Notifications page: a nil
// config.Recipients slice marshals to JSON `null`, and the frontend calls
// .join() on it unconditionally, throwing "Cannot read properties of null
// (reading 'join')". A zero-value config.NotificationsConfig{} (as returned
// when nothing has ever been persisted) must still serialize recipients as
// an empty array, never null.
func TestNotificationsHandler_GetConfig_RecipientsNeverNull(t *testing.T) {
	h, _, mock := newNotificationsHandler(t)
	mock.ExpectQuery("SELECT notifications_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow(nil))

	w := httptest.NewRecorder()
	r := gin.New()
	r.GET("/notifications/config", h.GetConfig)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/notifications/config", nil))

	if strings.Contains(w.Body.String(), `"recipients":null`) {
		t.Fatalf("recipients must never serialize as null, got body=%s", w.Body.String())
	}

	var resp NotificationsConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Recipients == nil {
		t.Error("resp.Recipients should be an empty (non-nil) slice, not nil")
	}
	if len(resp.Recipients) != 0 {
		t.Errorf("resp.Recipients = %v, want empty", resp.Recipients)
	}
}

func TestNotificationsHandler_GetConfig_PasswordConfiguredFromDB(t *testing.T) {
	h, _, mock := newNotificationsHandler(t)
	dbRow := `{"enabled":true,"smtp":{"host":"smtp.example.com","port":587,"from":"a@example.com","smtp_password_encrypted":"cipher"}}`
	mock.ExpectQuery("SELECT notifications_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow([]byte(dbRow)))

	w := httptest.NewRecorder()
	r := gin.New()
	r.GET("/notifications/config", h.GetConfig)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/notifications/config", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp NotificationsConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.PasswordConfigured {
		t.Error("expected password_configured=true when DB row has a stored ciphertext")
	}
}

// ---------------------------------------------------------------------------
// PutConfig (handler, sqlmock-backed)
// ---------------------------------------------------------------------------

func TestNotificationsHandler_PutConfig_ValidationError(t *testing.T) {
	h, _, _ := newNotificationsHandler(t)

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/notifications/config", h.PutConfig)
	body := `{"enabled":true,"smtp":{"from":"admin@example.com"}}` // missing host
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/notifications/config", strings.NewReader(body)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestNotificationsHandler_PutConfig_EmptyPasswordPreservesExisting(t *testing.T) {
	h, cfg, mock := newNotificationsHandler(t)

	existingRow := `{"enabled":true,"smtp":{"host":"old.example.com","port":587,"from":"old@example.com","smtp_password_encrypted":"existing-cipher"}}`
	mock.ExpectQuery("SELECT notifications_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow([]byte(existingRow)))
	mock.ExpectExec("UPDATE system_settings").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/notifications/config", h.PutConfig)
	body := `{"enabled":true,"smtp":{"host":"smtp.example.com","from":"admin@example.com","port":587}}` // no password
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/notifications/config", strings.NewReader(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	// The in-memory password must be left untouched (still empty here) since
	// the request omitted it.
	if cfg.SMTP.Password != "" {
		t.Errorf("cfg.SMTP.Password = %q, want unchanged empty string", cfg.SMTP.Password)
	}

	var resp NotificationsConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.PasswordConfigured {
		t.Error("expected password_configured=true (preserved from existing DB row)")
	}
	if resp.SMTP.Host != "smtp.example.com" {
		t.Errorf("SMTP.Host = %q, want %q", resp.SMTP.Host, "smtp.example.com")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestNotificationsHandler_PutConfig_SealsNewPassword(t *testing.T) {
	h, cfg, mock := newNotificationsHandler(t)

	mock.ExpectQuery("SELECT notifications_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow(nil))
	mock.ExpectExec("UPDATE system_settings").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r := gin.New()
	r.PUT("/notifications/config", h.PutConfig)
	body := `{"enabled":true,"smtp":{"host":"smtp.example.com","from":"admin@example.com","port":587,"password":"hunter2"}}`
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/notifications/config", strings.NewReader(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if cfg.SMTP.Password != "hunter2" {
		t.Errorf("cfg.SMTP.Password = %q, want %q (updated in place)", cfg.SMTP.Password, "hunter2")
	}

	var resp NotificationsConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.PasswordConfigured {
		t.Error("expected password_configured=true after sealing a new password")
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "hunter2") {
		t.Error("response must never include the plaintext password")
	}
}

// ---------------------------------------------------------------------------
// TestEmail (handler, validation-only — no live SMTP send in unit tests)
// ---------------------------------------------------------------------------

func TestNotificationsHandler_TestEmail_NoRecipients(t *testing.T) {
	h, _, _ := newNotificationsHandler(t)

	w := httptest.NewRecorder()
	r := gin.New()
	r.POST("/notifications/test", h.TestEmail)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notifications/test", strings.NewReader(`{}`)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (no recipients, no cve.email_recipients fallback), body=%s", w.Code, w.Body.String())
	}
}

func TestNotificationsHandler_TestEmail_NoHost(t *testing.T) {
	h, _, mock := newNotificationsHandler(t)
	mock.ExpectQuery("SELECT notifications_config FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"notifications_config"}).AddRow(nil))

	w := httptest.NewRecorder()
	r := gin.New()
	r.POST("/notifications/test", h.TestEmail)
	body := `{"recipients":["a@example.com"]}`
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notifications/test", strings.NewReader(body)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (no smtp host configured), body=%s", w.Code, w.Body.String())
	}
}
