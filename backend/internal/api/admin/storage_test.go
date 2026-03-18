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
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"

	// Register storage backends so storage.NewStorage works in tests
	_ "github.com/terraform-registry/terraform-registry/internal/storage/azure"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/gcs"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/local"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/s3"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var sysSettingsCols = []string{
	"id", "storage_configured", "storage_configured_at", "storage_configured_by",
	"created_at", "updated_at",
}

var storageConfigCols = []string{
	"id", "backend_type", "is_active",
	"local_base_path", "local_serve_directly",
	"azure_account_name", "azure_account_key_encrypted", "azure_container_name", "azure_cdn_url",
	"s3_endpoint", "s3_region", "s3_bucket", "s3_auth_method",
	"s3_access_key_id_encrypted", "s3_secret_access_key_encrypted",
	"s3_role_arn", "s3_role_session_name", "s3_external_id", "s3_web_identity_token_file",
	"gcs_bucket", "gcs_project_id", "gcs_auth_method", "gcs_credentials_file",
	"gcs_credentials_json_encrypted", "gcs_endpoint",
	"created_at", "updated_at", "created_by", "updated_by",
}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleSysSettingsRow() *sqlmock.Rows {
	return sqlmock.NewRows(sysSettingsCols).
		AddRow(1, true, nil, nil, time.Now(), time.Now())
}

// sampleStorageCfgRow returns an inactive StorageConfig row (safe to delete).
func sampleStorageCfgRow() *sqlmock.Rows {
	return sqlmock.NewRows(storageConfigCols).
		AddRow(
			knownUUID, "local", false, // id, backend_type, is_active
			nil, nil, // local_base_path, local_serve_directly
			nil, nil, nil, nil, // azure fields
			nil, nil, nil, nil, nil, nil, // s3 fields (6)
			nil, nil, nil, nil, // s3 extra fields
			nil, nil, nil, nil, nil, nil, // gcs fields (6)
			time.Now(), time.Now(), nil, nil, // created_at, updated_at, created_by, updated_by
		)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newStorageRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	return newStorageRouterWithCipher(t, nil)
}

// newStorageRouterWithCipher creates a test gin router with an optional tokenCipher.
// Use nil cipher for tests that do not exercise credential encryption.
// Use a real cipher (created via crypto.NewTokenCipher) for Azure/S3/GCS credential tests.
func newStorageRouterWithCipher(t *testing.T, cipher *crypto.TokenCipher) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	storageRepo := repositories.NewStorageConfigRepository(sqlxDB)
	h := NewStorageHandlers(&config.Config{}, storageRepo, cipher)

	r := gin.New()
	r.GET("/setup/status", h.GetSetupStatus)
	r.GET("/storage/config", h.GetActiveStorageConfig)
	r.GET("/storage/configs", h.ListStorageConfigs)
	r.GET("/storage/configs/:id", h.GetStorageConfig)
	r.POST("/storage/configs", h.CreateStorageConfig)
	r.PUT("/storage/configs/:id", h.UpdateStorageConfig)
	r.DELETE("/storage/configs/:id", h.DeleteStorageConfig)
	r.POST("/storage/configs/:id/activate", h.ActivateStorageConfig)
	r.POST("/storage/configs/test", h.TestStorageConfig)
	return mock, r
}

// ---------------------------------------------------------------------------
// GetSetupStatus
// ---------------------------------------------------------------------------

func TestStorageGetSetupStatus_Configured(t *testing.T) {
	mock, r := newStorageRouter(t)
	// IsStorageConfigured returns true
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(true))
	// GetSystemSettings returns row
	mock.ExpectQuery("SELECT.*FROM system_settings WHERE id = 1").
		WillReturnRows(sampleSysSettingsRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/setup/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["storage_configured"] != true {
		t.Errorf("storage_configured = %v, want true", resp["storage_configured"])
	}
}

func TestStorageGetSetupStatus_NotConfigured(t *testing.T) {
	mock, r := newStorageRouter(t)
	// IsStorageConfigured returns false (no rows → ErrNoRows → false)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))
	// GetSystemSettings returns no rows (nil)
	mock.ExpectQuery("SELECT.*FROM system_settings WHERE id = 1").
		WillReturnRows(sqlmock.NewRows(sysSettingsCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/setup/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["setup_required"] != true {
		t.Errorf("setup_required = %v, want true", resp["setup_required"])
	}
}

func TestStorageGetSetupStatus_DBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/setup/status", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetActiveStorageConfig
// ---------------------------------------------------------------------------

func TestStorageGetActiveConfig_NotFound(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE is_active = true").
		WillReturnRows(sqlmock.NewRows(storageConfigCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/config", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestStorageGetActiveConfig_DBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE is_active = true").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/config", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestStorageGetActiveConfig_Success(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE is_active = true").
		WillReturnRows(sampleActiveStorageCfgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/config", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["backend_type"] != "local" {
		t.Errorf("backend_type = %v, want local", resp["backend_type"])
	}
	if resp["is_active"] != true {
		t.Errorf("is_active = %v, want true", resp["is_active"])
	}
}

// ---------------------------------------------------------------------------
// ListStorageConfigs
// ---------------------------------------------------------------------------

func TestStorageListConfigs_Empty(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config.*ORDER BY").
		WillReturnRows(sqlmock.NewRows(storageConfigCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/configs", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageListConfigs_DBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config.*ORDER BY").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/configs", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestStorageListConfigs_Success(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config.*ORDER BY").
		WillReturnRows(sampleStorageCfgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/configs", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	var items []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("len = %d, want 1", len(items))
	}
	if items[0]["backend_type"] != "local" {
		t.Errorf("backend_type = %v, want local", items[0]["backend_type"])
	}
}

// ---------------------------------------------------------------------------
// GetStorageConfig
// ---------------------------------------------------------------------------

func TestStorageGetConfig_InvalidID(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/configs/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestStorageGetConfig_NotFound(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sqlmock.NewRows(storageConfigCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/configs/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestStorageGetConfig_Success(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/configs/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["backend_type"] != "local" {
		t.Errorf("backend_type = %v, want local", resp["backend_type"])
	}
	if resp["id"] != knownUUID {
		t.Errorf("id = %v, want %s", resp["id"], knownUUID)
	}
}

// ---------------------------------------------------------------------------
// CreateStorageConfig
// ---------------------------------------------------------------------------

func TestStorageCreateConfig_InvalidBackend(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type": "invalid-backend",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_LocalSuccess(t *testing.T) {
	mock, r := newStorageRouter(t)
	// IsStorageConfigured → no rows → false
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))
	// CreateStorageConfig INSERT
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/tmp/storage",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteStorageConfig
// ---------------------------------------------------------------------------

func TestStorageDeleteConfig_InvalidID(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/storage/configs/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestStorageDeleteConfig_NotFound(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sqlmock.NewRows(storageConfigCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/storage/configs/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestStorageDeleteConfig_Success(t *testing.T) {
	mock, r := newStorageRouter(t)
	// GetStorageConfig returns inactive config (is_active=false)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	mock.ExpectExec("DELETE FROM storage_config WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/storage/configs/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ActivateStorageConfig
// ---------------------------------------------------------------------------

func TestStorageActivateConfig_InvalidID(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/not-a-uuid/activate", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestStorageActivateConfig_NotFound(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sqlmock.NewRows(storageConfigCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/"+knownUUID+"/activate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// sampleActiveStorageCfgRow returns an active local StorageConfig row.
func sampleActiveStorageCfgRow() *sqlmock.Rows {
	return sqlmock.NewRows(storageConfigCols).
		AddRow(
			knownUUID, "local", true, // id, backend_type, is_active
			nil, nil, // local_base_path, local_serve_directly
			nil, nil, nil, nil, // azure fields
			nil, nil, nil, nil, nil, nil, // s3 fields
			nil, nil, nil, nil, // s3 extra fields
			nil, nil, nil, nil, nil, nil, // gcs fields
			time.Now(), time.Now(), nil, nil, // timestamps
		)
}

// ---------------------------------------------------------------------------
// UpdateStorageConfig tests
// ---------------------------------------------------------------------------

func TestStorageUpdateConfig_InvalidID(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/not-a-uuid",
		bytes.NewBufferString(`{"backend_type":"local","local_base_path":"/data"}`)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestStorageUpdateConfig_NotFound(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sqlmock.NewRows(storageConfigCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(`{"backend_type":"local","local_base_path":"/data"}`)))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageUpdateConfig_GetDBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(`{"backend_type":"local","local_base_path":"/data"}`)))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageUpdateConfig_InvalidBody(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	// IsStorageConfigured
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))

	w := httptest.NewRecorder()
	// backend_type is required but missing
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(`{}`)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageUpdateConfig_ValidateLocalMissingPath(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))

	// local backend but no local_base_path
	body := `{"backend_type":"local"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(body)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageUpdateConfig_ActiveConfigBackendTypeChange(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleActiveStorageCfgRow()) // is_active = true, backend_type = "local"
	// IsStorageConfigured returns true
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(true))

	// Attempt to change backend_type from "local" to "s3"
	body := `{"backend_type":"s3","s3_bucket":"mybucket","s3_region":"us-east-1"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(body)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (cannot change active config backend type): body=%s", w.Code, w.Body.String())
	}
}

func TestStorageUpdateConfig_Success(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow()) // inactive, backend_type = local
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))
	// UPDATE storage_config SET ...
	mock.ExpectExec("UPDATE storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{"backend_type":"local","local_base_path":"/new/data"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageUpdateConfig_UpdateDBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))
	mock.ExpectExec("UPDATE storage_config").
		WillReturnError(errDB)

	body := `{"backend_type":"local","local_base_path":"/new/data"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(body)))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TestStorageConfig
// ---------------------------------------------------------------------------

func TestTestStorageConfig_InvalidBody(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/test",
		bytes.NewBufferString("not-json")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestStorageConfig_ValidLocalConfig(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	// Use jsonBody to properly escape the path (handles backslashes on Windows).
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/test",
		jsonBody(map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": t.TempDir(),
		})))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestTestStorageConfig_LocalMissingPath(t *testing.T) {
	_, r := newStorageRouter(t)
	body := `{"backend_type":"local"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/test",
		bytes.NewBufferString(body)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestStorageConfig_ValidAzureConfig(t *testing.T) {
	_, r := newStorageRouter(t)
	// azure_account_key must be valid base64; "dGVzdA==" = base64("test")
	body := `{"backend_type":"azure","azure_account_name":"acct","azure_container_name":"ctr","azure_account_key":"dGVzdA=="}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/test",
		bytes.NewBufferString(body)))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestTestStorageConfig_AzureMissingKey(t *testing.T) {
	_, r := newStorageRouter(t)
	body := `{"backend_type":"azure","azure_account_name":"acct","azure_container_name":"ctr"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/test",
		bytes.NewBufferString(body)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestStorageConfig_ValidS3Config(t *testing.T) {
	_, r := newStorageRouter(t)
	// use 'default' (AWS default credential chain) so New() succeeds
	body := `{"backend_type":"s3","s3_bucket":"my-bucket","s3_region":"us-east-1","s3_auth_method":"default"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/test",
		bytes.NewBufferString(body)))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestTestStorageConfig_S3StaticMissingKeys(t *testing.T) {
	_, r := newStorageRouter(t)
	body := `{"backend_type":"s3","s3_bucket":"b","s3_region":"us-east-1","s3_auth_method":"static"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/test",
		bytes.NewBufferString(body)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestTestStorageConfig_ValidGCSConfig(t *testing.T) {
	_, r := newStorageRouter(t)
	body := `{"backend_type":"gcs","gcs_bucket":"my-bucket","gcs_auth_method":"workload_identity"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/test",
		bytes.NewBufferString(body)))
	// In environments without GCP Application Default Credentials, NewClient fails
	// and the handler returns 400.  In GCP environments it returns 200.
	// Both are valid test outcomes; we only fail on unexpected status codes.
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 200 or 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTestStorageConfig_GCSServiceAccountMissingCreds(t *testing.T) {
	_, r := newStorageRouter(t)
	body := `{"backend_type":"gcs","gcs_bucket":"b","gcs_auth_method":"service_account"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/test",
		bytes.NewBufferString(body)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateStorageConfig — additional backend types
// ---------------------------------------------------------------------------

func TestStorageCreateConfig_S3IAMSuccess(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"})) // not configured
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":   "s3",
			"s3_bucket":      "my-bucket",
			"s3_region":      "us-east-1",
			"s3_auth_method": "iam",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_GCSWorkloadIdentitySuccess(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":    "gcs",
			"gcs_bucket":      "my-gcs-bucket",
			"gcs_auth_method": "workload_identity",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_AzureSuccess(t *testing.T) {
	cipher, err := crypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	mock, r := newStorageRouterWithCipher(t, cipher)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// azure_account_key is required by validation; base64("test") = "dGVzdA=="
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":         "azure",
			"azure_account_name":   "myaccount",
			"azure_container_name": "mycontainer",
			"azure_account_key":    "dGVzdA==",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_AlreadyConfiguredDeactivates(t *testing.T) {
	mock, r := newStorageRouter(t)
	// IsStorageConfigured returns true
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(true))
	// DeactivateAllStorageConfigs
	mock.ExpectExec("UPDATE storage_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(1, 2))
	// CreateStorageConfig INSERT
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/tmp/new-storage",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_DeactivateError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(true))
	mock.ExpectExec("UPDATE storage_config SET is_active = false").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/tmp/storage",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_InsertDBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/tmp/storage",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ActivateStorageConfig — success and error paths
// ---------------------------------------------------------------------------

func TestStorageActivateConfig_GetDBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/"+knownUUID+"/activate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestStorageActivateConfig_ActivateDBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE storage_config SET is_active = false").
		WillReturnError(errDB)
	mock.ExpectRollback()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/"+knownUUID+"/activate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestStorageActivateConfig_Success(t *testing.T) {
	mock, r := newStorageRouter(t)
	// First GetStorageConfig
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	// ActivateStorageConfig transaction
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE storage_config SET is_active = false").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE storage_config SET is_active = true").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	// Second GetStorageConfig (refresh)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleActiveStorageCfgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs/"+knownUUID+"/activate", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateStorageConfig — additional backend types (hits updateStorageConfigFromInput)
// ---------------------------------------------------------------------------

func TestStorageUpdateConfig_S3Success(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow()) // inactive local config
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))
	mock.ExpectExec("UPDATE storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{"backend_type":"s3","s3_bucket":"new-bucket","s3_region":"eu-west-1","s3_auth_method":"iam"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageUpdateConfig_GCSSuccess(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))
	mock.ExpectExec("UPDATE storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	body := `{"backend_type":"gcs","gcs_bucket":"my-gcs-bucket","gcs_auth_method":"workload_identity"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageUpdateConfig_AzureSuccess(t *testing.T) {
	cipher, err := crypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	mock, r := newStorageRouterWithCipher(t, cipher)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))
	mock.ExpectExec("UPDATE storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// azure_account_key required by validation; base64("test") = "dGVzdA=="
	body := `{"backend_type":"azure","azure_account_name":"acct","azure_container_name":"ctr","azure_account_key":"dGVzdA==","azure_cdn_url":"https://cdn.example.com"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteStorageConfig — additional paths
// ---------------------------------------------------------------------------

func TestStorageDeleteConfig_GetDBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/storage/configs/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestStorageDeleteConfig_ActiveConfig(t *testing.T) {
	mock, r := newStorageRouter(t)
	// Return an active config
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleActiveStorageCfgRow()) // is_active = true

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/storage/configs/"+knownUUID, nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (cannot delete active config)", w.Code)
	}
}

func TestStorageDeleteConfig_DeleteDBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	// Get inactive config
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	// DELETE fails
	mock.ExpectExec("DELETE FROM storage_config WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/storage/configs/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetSetupStatus — additional coverage paths
// ---------------------------------------------------------------------------

func TestStorageGetSetupStatus_SystemSettingsError(t *testing.T) {
	mock, r := newStorageRouter(t)
	// IsStorageConfigured succeeds
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(true))
	// GetSystemSettings fails
	mock.ExpectQuery("SELECT.*FROM system_settings WHERE id = 1").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/setup/status", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestStorageGetSetupStatus_WithConfiguredTimestamp(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(true))
	ts := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT.*FROM system_settings WHERE id = 1").
		WillReturnRows(sqlmock.NewRows(sysSettingsCols).
			AddRow(1, true, ts, nil, time.Now(), time.Now()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/setup/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["storage_configured_at"] == nil {
		t.Error("expected storage_configured_at in response")
	}
}

// ---------------------------------------------------------------------------
// GetStorageConfig — DB error path
// ---------------------------------------------------------------------------

func TestStorageGetConfig_DBError(t *testing.T) {
	mock, r := newStorageRouter(t)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/storage/configs/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateStorageConfig — additional coverage paths
// ---------------------------------------------------------------------------

func TestStorageCreateConfig_InvalidBody(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		bytes.NewBufferString("not-json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_ValidationErrorLocalMissingPath(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type": "local",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_CheckConfiguredError(t *testing.T) {
	mock, r := newStorageRouter(t)
	// IsStorageConfigured returns DB error
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/tmp/storage",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_S3StaticSuccess(t *testing.T) {
	cipher, err := crypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	mock, r := newStorageRouterWithCipher(t, cipher)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":         "s3",
			"s3_bucket":            "my-bucket",
			"s3_region":            "us-east-1",
			"s3_auth_method":       "static",
			"s3_access_key_id":     "AKIATEST",
			"s3_secret_access_key": "secret123",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_GCSServiceAccountSuccess(t *testing.T) {
	cipher, err := crypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	mock, r := newStorageRouterWithCipher(t, cipher)
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":         "gcs",
			"gcs_bucket":           "my-gcs-bucket",
			"gcs_auth_method":      "service_account",
			"gcs_credentials_json": `{"type":"service_account","project_id":"test"}`,
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_S3AssumeRoleMissingARN(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":   "s3",
			"s3_bucket":      "my-bucket",
			"s3_region":      "us-east-1",
			"s3_auth_method": "assume_role",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_S3OidcMissingARN(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":   "s3",
			"s3_bucket":      "my-bucket",
			"s3_region":      "us-east-1",
			"s3_auth_method": "oidc",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_GCSServiceAccountMissingCreds(t *testing.T) {
	_, r := newStorageRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":    "gcs",
			"gcs_bucket":      "my-gcs-bucket",
			"gcs_auth_method": "service_account",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageCreateConfig_WithUserContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	storageRepo := repositories.NewStorageConfigRepository(sqlxDB)
	h := NewStorageHandlers(&config.Config{}, storageRepo, nil)

	r := gin.New()
	// Add middleware that sets user_id in context before the handler
	r.POST("/storage/configs", func(c *gin.Context) {
		c.Set("user_id", uuid.MustParse(knownUUID))
	}, h.CreateStorageConfig)

	// IsStorageConfigured: not configured
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}))
	// CreateStorageConfig INSERT
	mock.ExpectExec("INSERT INTO storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// SetStorageConfigured UPDATE (triggered because !configured && userUUID.Valid)
	mock.ExpectExec("UPDATE system_settings SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/storage/configs",
		jsonBody(map[string]interface{}{
			"backend_type":    "local",
			"local_base_path": "/tmp/storage",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateStorageConfig — S3/GCS credential encryption paths
// ---------------------------------------------------------------------------

func TestStorageUpdateConfig_S3StaticWithKeysSuccess(t *testing.T) {
	cipher, err := crypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	mock, r := newStorageRouterWithCipher(t, cipher)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))
	mock.ExpectExec("UPDATE storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		jsonBody(map[string]interface{}{
			"backend_type":         "s3",
			"s3_bucket":            "my-bucket",
			"s3_region":            "us-east-1",
			"s3_auth_method":       "static",
			"s3_access_key_id":     "AKIATEST",
			"s3_secret_access_key": "secret123",
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestStorageUpdateConfig_GCSServiceAccountWithCredsSuccess(t *testing.T) {
	cipher, err := crypto.NewTokenCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewTokenCipher: %v", err)
	}
	mock, r := newStorageRouterWithCipher(t, cipher)
	mock.ExpectQuery("SELECT.*FROM storage_config WHERE id").
		WillReturnRows(sampleStorageCfgRow())
	mock.ExpectQuery("SELECT storage_configured FROM system_settings").
		WillReturnRows(sqlmock.NewRows([]string{"storage_configured"}).AddRow(false))
	mock.ExpectExec("UPDATE storage_config").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/storage/configs/"+knownUUID,
		jsonBody(map[string]interface{}{
			"backend_type":         "gcs",
			"gcs_bucket":           "my-gcs-bucket",
			"gcs_auth_method":      "service_account",
			"gcs_credentials_json": `{"type":"service_account","project_id":"test"}`,
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}
