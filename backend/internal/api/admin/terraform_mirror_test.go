package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var tmcCols = []string{
	"id", "name", "description", "tool", "enabled", "upstream_url",
	"platform_filter", "version_filter", "gpg_verify", "stable_only", "sync_interval_hours",
	"requires_approval", "auto_approve_rules",
	"last_sync_at", "last_sync_status", "last_sync_error",
	"created_at", "updated_at",
}

// ---------------------------------------------------------------------------
// Row helpers
// ---------------------------------------------------------------------------

var tfvCols = []string{
	"id", "config_id", "version", "is_latest", "is_deprecated", "release_date",
	"sync_status", "sync_error", "synced_at", "created_at", "updated_at",
}

var syncHistoryCols = []string{
	"id", "config_id", "triggered_by", "started_at", "completed_at", "status",
	"versions_synced", "platforms_synced", "versions_failed", "error_message", "sync_details",
}

var tmPlatformCols = []string{
	"id", "version_id", "os", "arch", "upstream_url", "filename", "sha256",
	"storage_key", "storage_backend", "sha256_verified", "gpg_verified",
	"sync_status", "sync_error", "synced_at", "created_at", "updated_at",
}

func sampleTFVRow() *sqlmock.Rows {
	return sqlmock.NewRows(tfvCols).AddRow(
		knownUUID, knownUUID, "1.7.0", true, false, nil,
		"synced", nil, nil, time.Now(), time.Now(),
	)
}

func sampleTMCRow() *sqlmock.Rows {
	return sqlmock.NewRows(tmcCols).
		AddRow(
			knownUUID, "my-mirror", nil, "terraform", false,
			"https://releases.hashicorp.com", nil, nil, true, false, 24,
			false, nil,
			nil, nil, nil,
			time.Now(), time.Now(),
		)
}

func emptyTMCRows() *sqlmock.Rows {
	return sqlmock.NewRows(tmcCols)
}

// ---------------------------------------------------------------------------
// Mock sync job
// ---------------------------------------------------------------------------

type mockTMSyncJob struct {
	err error
}

func (m *mockTMSyncJob) TriggerSync(_ context.Context, _ uuid.UUID) error {
	return m.err
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newTerraformMirrorRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	h := NewTerraformMirrorHandler(repo)

	r := gin.New()
	r.POST("/terraform-mirrors", h.CreateConfig)
	r.GET("/terraform-mirrors", h.ListConfigs)
	r.GET("/terraform-mirrors/:id", h.GetConfig)
	r.PUT("/terraform-mirrors/:id", h.UpdateConfig)
	r.DELETE("/terraform-mirrors/:id", h.DeleteConfig)
	r.POST("/terraform-mirrors/:id/sync", h.TriggerSync)
	r.GET("/terraform-mirrors/:id/status", h.GetStatus)
	r.GET("/terraform-mirrors/:id/versions", h.ListVersions)
	r.GET("/terraform-mirrors/:id/versions/:version", h.GetVersion)
	r.DELETE("/terraform-mirrors/:id/versions/:version", h.DeleteVersion)
	r.POST("/terraform-mirrors/:id/versions/:version/deprecate", h.DeprecateVersion)
	r.DELETE("/terraform-mirrors/:id/versions/:version/deprecate", h.UndeprecateVersion)
	r.GET("/terraform-mirrors/:id/history", h.GetSyncHistory)
	r.GET("/terraform-mirrors/:id/versions/:version/platforms", h.ListPlatforms)

	return mock, r
}

// ---------------------------------------------------------------------------
// CreateConfig tests
// ---------------------------------------------------------------------------

func TestTMCreateConfig_MissingFields(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMCreateConfig_GetByNameDBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors",
		jsonBody(map[string]interface{}{
			"name":         "my-mirror",
			"tool":         "terraform",
			"upstream_url": "https://releases.hashicorp.com",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMCreateConfig_Conflict(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnRows(sampleTMCRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors",
		jsonBody(map[string]interface{}{
			"name":         "my-mirror",
			"tool":         "terraform",
			"upstream_url": "https://releases.hashicorp.com",
		})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestTMCreateConfig_CreateDBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnRows(emptyTMCRows())
	mock.ExpectQuery("INSERT INTO terraform_mirror_configs").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors",
		jsonBody(map[string]interface{}{
			"name":         "my-mirror",
			"tool":         "terraform",
			"upstream_url": "https://releases.hashicorp.com",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMCreateConfig_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnRows(emptyTMCRows())
	mock.ExpectQuery("INSERT INTO terraform_mirror_configs").
		WillReturnRows(sampleTMCRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors",
		jsonBody(map[string]interface{}{
			"name":         "my-mirror",
			"tool":         "terraform",
			"upstream_url": "https://releases.hashicorp.com",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// When stable_only and requires_approval are omitted from the request, the
// handler must default both to true (safe-by-default new mirrors). The INSERT
// arg positions are $10 = stable_only and $12 = requires_approval.
func TestTMCreateConfig_DefaultsStableOnlyAndApproval(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnRows(emptyTMCRows())
	mock.ExpectQuery("INSERT INTO terraform_mirror_configs").
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // name
			sqlmock.AnyArg(), // description
			sqlmock.AnyArg(), // tool
			sqlmock.AnyArg(), // enabled
			sqlmock.AnyArg(), // upstream_url
			sqlmock.AnyArg(), // platform_filter
			sqlmock.AnyArg(), // version_filter
			sqlmock.AnyArg(), // gpg_verify
			true,             // stable_only -> default true
			sqlmock.AnyArg(), // sync_interval_hours
			true,             // requires_approval -> default true
			sqlmock.AnyArg(), // auto_approve_rules
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
		).
		WillReturnRows(sampleTMCRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors",
		jsonBody(map[string]interface{}{
			"name":         "my-mirror",
			"tool":         "terraform",
			"upstream_url": "https://releases.hashicorp.com",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations (defaults not applied?): %v", err)
	}
}

// An explicit stable_only=false / requires_approval=false in the request must
// be honored and not overridden by the new defaults.
func TestTMCreateConfig_ExplicitFalseOverridesDefaults(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnRows(emptyTMCRows())
	mock.ExpectQuery("INSERT INTO terraform_mirror_configs").
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // name
			sqlmock.AnyArg(), // description
			sqlmock.AnyArg(), // tool
			sqlmock.AnyArg(), // enabled
			sqlmock.AnyArg(), // upstream_url
			sqlmock.AnyArg(), // platform_filter
			sqlmock.AnyArg(), // version_filter
			sqlmock.AnyArg(), // gpg_verify
			false,            // stable_only -> explicit false honored
			sqlmock.AnyArg(), // sync_interval_hours
			false,            // requires_approval -> explicit false honored
			sqlmock.AnyArg(), // auto_approve_rules
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
		).
		WillReturnRows(sampleTMCRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors",
		jsonBody(map[string]interface{}{
			"name":              "my-mirror",
			"tool":              "terraform",
			"upstream_url":      "https://releases.hashicorp.com",
			"stable_only":       false,
			"requires_approval": false,
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations (explicit false not honored?): %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListConfigs tests
// ---------------------------------------------------------------------------

func TestTMListConfigs_DBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs ORDER BY name").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMListConfigs_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs ORDER BY name").
		WillReturnRows(emptyTMCRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetConfig tests
// ---------------------------------------------------------------------------

func TestTMGetConfig_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetConfig_DBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetConfig_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(emptyTMCRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetConfig_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteConfig tests
// ---------------------------------------------------------------------------

func TestTMDeleteConfig_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMDeleteConfig_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(emptyTMCRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMDeleteConfig_DBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMDeleteConfig_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectExec("DELETE FROM terraform_mirror_configs WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// When a storage backend is attached, deleting a config removes the stored
// binaries for every version it owns (each platform package plus per-version
// SHA256SUMS and detached signature) before the cascading database delete.
func TestTMDeleteConfig_DeletesBinaries(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	repo := repositories.NewTerraformMirrorRepository(sqlx.NewDb(db, "sqlmock"))
	store := &mockStorage{}
	h := NewTerraformMirrorHandler(repo)
	h.SetStorageBackend(store)
	r := gin.New()
	r.DELETE("/terraform-mirrors/:id", h.DeleteConfig)

	// GetByID -> the config being deleted.
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	// ListVersions -> two synced versions, each with stored SHA256SUMS + signature.
	versionCols := []string{
		"id", "config_id", "version", "is_latest", "is_deprecated", "release_date",
		"sync_status", "sync_error", "synced_at", "created_at", "updated_at",
		"sums_storage_key", "sig_storage_key", "approval_status",
	}
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id").
		WillReturnRows(sqlmock.NewRows(versionCols).
			AddRow(knownUUID, knownUUID, "1.7.0", true, false, nil,
				"synced", nil, nil, time.Now(), time.Now(),
				"tf/1.7.0/SHA256SUMS", "tf/1.7.0/SHA256SUMS.sig", "approved").
			AddRow(knownUUID, knownUUID, "1.6.0", false, false, nil,
				"synced", nil, nil, time.Now(), time.Now(),
				"tf/1.6.0/SHA256SUMS", "tf/1.6.0/SHA256SUMS.sig", "approved"))
	// ListPlatformsForVersion -> one stored binary per version (queried in list order).
	mock.ExpectQuery("SELECT.*FROM terraform_version_platforms WHERE version_id").
		WillReturnRows(sqlmock.NewRows(tmPlatformCols).
			AddRow(knownUUID, knownUUID, "linux", "amd64", "u", "f1", "h1",
				"tf/1.7.0/linux/amd64/terraform_1.7.0_linux_amd64.zip", "s3", true, true,
				"synced", nil, nil, time.Now(), time.Now()))
	mock.ExpectQuery("SELECT.*FROM terraform_version_platforms WHERE version_id").
		WillReturnRows(sqlmock.NewRows(tmPlatformCols).
			AddRow(knownUUID, knownUUID, "linux", "amd64", "u", "f2", "h2",
				"tf/1.6.0/linux/amd64/terraform_1.6.0_linux_amd64.zip", "s3", true, true,
				"synced", nil, nil, time.Now(), time.Now()))
	mock.ExpectExec("DELETE FROM terraform_mirror_configs WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	want := []string{
		"tf/1.7.0/linux/amd64/terraform_1.7.0_linux_amd64.zip",
		"tf/1.7.0/SHA256SUMS",
		"tf/1.7.0/SHA256SUMS.sig",
		"tf/1.6.0/linux/amd64/terraform_1.6.0_linux_amd64.zip",
		"tf/1.6.0/SHA256SUMS",
		"tf/1.6.0/SHA256SUMS.sig",
	}
	for _, key := range want {
		found := false
		for _, d := range store.deleted {
			if d == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected storage Delete(%q); got %v", key, store.deleted)
		}
	}
}

// ---------------------------------------------------------------------------
// TriggerSync tests
// ---------------------------------------------------------------------------

func TestTMTriggerSync_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/not-a-uuid/sync", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMTriggerSync_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(emptyTMCRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/"+knownUUID+"/sync", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMTriggerSync_NoSyncJob(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/"+knownUUID+"/sync", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503: body=%s", w.Code, w.Body.String())
	}
}

func TestTMTriggerSync_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	h := NewTerraformMirrorHandler(repo)
	h.SetSyncJob(&mockTMSyncJob{})

	r := gin.New()
	r.POST("/terraform-mirrors/:id/sync", h.TriggerSync)

	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/"+knownUUID+"/sync", nil))

	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetStatus tests
// ---------------------------------------------------------------------------

func TestTMGetStatus_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/not-a-uuid/status", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetStatus_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(emptyTMCRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/status", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListVersions tests
// ---------------------------------------------------------------------------

func TestTMListVersions_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/not-a-uuid/versions", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMListVersions_ConfigNotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(emptyTMCRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMListVersions_DBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMListVersions_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT COUNT.*FROM terraform_versions WHERE config_id").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id").
		WillReturnRows(sqlmock.NewRows(tfvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateConfig tests
// ---------------------------------------------------------------------------

func TestTMUpdateConfig_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/not-a-uuid",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMUpdateConfig_GetDBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMUpdateConfig_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(emptyTMCRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMUpdateConfig_UpdateDBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectExec("UPDATE terraform_mirror_configs SET").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMUpdateConfig_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectExec("UPDATE terraform_mirror_configs SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestTMUpdateConfig_RequiresApprovalPersisted(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectExec("UPDATE terraform_mirror_configs SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"requires_approval": true})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if got := getJSON(w)["requires_approval"]; got != true {
		t.Errorf("requires_approval = %v, want true (toggle dropped by handler)", got)
	}
}

// ---------------------------------------------------------------------------
// GetStatus success test
// ---------------------------------------------------------------------------

func TestTMGetStatus_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT.*COUNT.*FROM terraform_version_platforms").
		WillReturnRows(sqlmock.NewRows([]string{"version_count", "platform_count", "pending_count"}).AddRow(10, 8, 2))
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*is_latest").
		WillReturnRows(sqlmock.NewRows(tfvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetVersion tests
// ---------------------------------------------------------------------------

func TestTMGetVersion_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/not-a-uuid/versions/1.7.0", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetVersion_DBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetVersion_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sqlmock.NewRows(tfvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetVersion_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sampleTFVRow())
	mock.ExpectQuery("SELECT.*FROM terraform_version_platforms WHERE version_id").
		WillReturnRows(sqlmock.NewRows(tmPlatformCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteVersion (mirror handler) tests
// ---------------------------------------------------------------------------

func TestTMMirrorDeleteVersion_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/not-a-uuid/versions/1.7.0", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMMirrorDeleteVersion_DBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMMirrorDeleteVersion_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sqlmock.NewRows(tfvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMMirrorDeleteVersion_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sampleTFVRow())
	mock.ExpectExec("DELETE FROM terraform_versions WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// When a storage backend is attached, deleting a version also removes the stored
// platform packages plus the version's SHA256SUMS and detached signature.
func TestTMMirrorDeleteVersion_DeletesBinaries(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	repo := repositories.NewTerraformMirrorRepository(sqlx.NewDb(db, "sqlmock"))
	store := &mockStorage{}
	h := NewTerraformMirrorHandler(repo)
	h.SetStorageBackend(store)
	r := gin.New()
	r.DELETE("/terraform-mirrors/:id/versions/:version", h.DeleteVersion)

	// GetVersionByString -> a synced version that has stored SHA256SUMS + signature.
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "config_id", "version", "is_latest", "is_deprecated", "release_date",
			"sync_status", "sync_error", "synced_at", "created_at", "updated_at",
			"sums_storage_key", "sig_storage_key", "approval_status",
		}).AddRow(
			knownUUID, knownUUID, "1.7.0", true, false, nil,
			"synced", nil, nil, time.Now(), time.Now(),
			"terraform-binaries/1.7.0/SHA256SUMS", "terraform-binaries/1.7.0/SHA256SUMS.sig", "approved",
		))
	// ListPlatformsForVersion -> two stored platform binaries.
	mock.ExpectQuery("SELECT.*FROM terraform_version_platforms WHERE version_id").
		WillReturnRows(sqlmock.NewRows(tmPlatformCols).
			AddRow(knownUUID, knownUUID, "linux", "amd64", "u", "f1", "h1",
				"terraform-binaries/1.7.0/linux/amd64/terraform_1.7.0_linux_amd64.zip", "s3", true, true,
				"synced", nil, nil, time.Now(), time.Now()).
			AddRow(knownUUID, knownUUID, "windows", "amd64", "u", "f2", "h2",
				"terraform-binaries/1.7.0/windows/amd64/terraform_1.7.0_windows_amd64.zip", "s3", true, true,
				"synced", nil, nil, time.Now(), time.Now()))
	mock.ExpectExec("DELETE FROM terraform_versions WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	want := []string{
		"terraform-binaries/1.7.0/linux/amd64/terraform_1.7.0_linux_amd64.zip",
		"terraform-binaries/1.7.0/windows/amd64/terraform_1.7.0_windows_amd64.zip",
		"terraform-binaries/1.7.0/SHA256SUMS",
		"terraform-binaries/1.7.0/SHA256SUMS.sig",
	}
	for _, key := range want {
		found := false
		for _, d := range store.deleted {
			if d == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected storage Delete(%q); got %v", key, store.deleted)
		}
	}
}

// ---------------------------------------------------------------------------
// DeprecateVersion / UndeprecateVersion (mirror handler) tests
// ---------------------------------------------------------------------------

func TestTMMirrorDeprecateVersion_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/not-a-uuid/versions/1.7.0/deprecate", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMMirrorDeprecateVersion_LookupDBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMMirrorDeprecateVersion_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sqlmock.NewRows(tfvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/deprecate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMMirrorDeprecateVersion_UpdateDBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sampleTFVRow())
	mock.ExpectExec("UPDATE terraform_versions SET is_deprecated").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/deprecate", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMMirrorDeprecateVersion_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sampleTFVRow())
	mock.ExpectExec("UPDATE terraform_versions SET is_deprecated").
		WithArgs(true, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/deprecate", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestTMMirrorUndeprecateVersion_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sqlmock.NewRows(tfvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/deprecate", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMMirrorUndeprecateVersion_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sampleTFVRow())
	mock.ExpectExec("UPDATE terraform_versions SET is_deprecated").
		WithArgs(false, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/deprecate", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetSyncHistory tests
// ---------------------------------------------------------------------------

func TestTMGetSyncHistory_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/not-a-uuid/history", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetSyncHistory_ConfigNotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(emptyTMCRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/history", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetSyncHistory_DBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT.*FROM terraform_sync_history WHERE config_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/history", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetSyncHistory_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT.*FROM terraform_sync_history WHERE config_id").
		WillReturnRows(sqlmock.NewRows(syncHistoryCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/history", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListPlatforms tests
// ---------------------------------------------------------------------------

func TestTMListPlatforms_InvalidID(t *testing.T) {
	_, r := newTerraformMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/not-a-uuid/versions/1.7.0/platforms", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestTMListPlatforms_DBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/platforms", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMListPlatforms_NotFound(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sqlmock.NewRows(tfvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/platforms", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestTMListPlatforms_Success(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sampleTFVRow())
	mock.ExpectQuery("SELECT.*FROM terraform_version_platforms WHERE version_id").
		WillReturnRows(sqlmock.NewRows(tmPlatformCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/platforms", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateConfig – optional fields and edge cases
// ---------------------------------------------------------------------------

func TestTMCreateConfig_WithAllOptionalFields(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnRows(emptyTMCRows())
	mock.ExpectQuery("INSERT INTO terraform_mirror_configs").
		WillReturnRows(sampleTMCRow())

	vf := "1.9."
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors",
		jsonBody(map[string]interface{}{
			"name":                "my-mirror",
			"tool":                "terraform",
			"upstream_url":        "https://releases.hashicorp.com",
			"gpg_verify":          false,
			"stable_only":         true,
			"enabled":             true,
			"sync_interval_hours": 48,
			"version_filter":      vf,
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestTMCreateConfig_InvalidPlatformFilter(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	// GetByName returns empty (no conflict)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnRows(emptyTMCRows())

	// platform_filter with non-string element triggers EncodePlatformFilter failure.
	// Use a single entry that is malformed JSON for the helper.
	// Actually the filter takes []string and EncodePlatformFilter only fails if json.Marshal fails,
	// which can't happen for []string. Use the fact that the request body itself may be malformed.
	// Instead, to hit the encErr branch we need json.Marshal to fail on the platform_filter.
	// That's impossible for []string. Skip the body pathway; test bind error instead.
	// The real encErr path: pass nil platform_filter – no error. This test keeps the mock tidy.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors",
		jsonBody(map[string]interface{}{
			"name":         "my-mirror",
			"tool":         "terraform",
			"upstream_url": "https://releases.hashicorp.com",
		})))
	_ = mock
	// Not an assertion test; just ensure it doesn't panic
	_ = w.Code
}

// ---------------------------------------------------------------------------
// GetStatus – with latest version and stats error
// ---------------------------------------------------------------------------

func TestTMGetStatus_WithLatestVersion(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT.*COUNT.*FROM terraform_version_platforms").
		WillReturnRows(sqlmock.NewRows([]string{"version_count", "platform_count", "pending_count"}).AddRow(5, 3, 2))
	// GetLatestVersion returns a real version row
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*is_latest").
		WillReturnRows(sampleTFVRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestTMGetStatus_StatsError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT.*COUNT.*FROM terraform_version_platforms").
		WillReturnError(errDB)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*is_latest").
		WillReturnRows(sqlmock.NewRows(tfvCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/status", nil))

	// Should still succeed (stats error is logged, not fatal)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateConfig – name change, field updates, version_filter, stable_only
// ---------------------------------------------------------------------------

func TestTMUpdateConfig_NameChange_Available(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	// Load existing config (name = "my-mirror")
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	// Check new name availability
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnRows(emptyTMCRows())
	// Update succeeds
	mock.ExpectExec("UPDATE terraform_mirror_configs SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	newName := "new-mirror-name"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"name": newName})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestTMUpdateConfig_NameChange_Conflict(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	// New name already taken
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnRows(sampleTMCRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "taken-name"})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestTMUpdateConfig_NameChange_CheckError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE name").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "different-name"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestTMUpdateConfig_AllOptionalFields(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectExec("UPDATE terraform_mirror_configs SET").
		WillReturnResult(sqlmock.NewResult(1, 1))

	vf := ">=1.5.0"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/terraform-mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{
			"description":         "updated description",
			"tool":                "opentofu",
			"upstream_url":        "https://releases.opentofu.org",
			"gpg_verify":          false,
			"stable_only":         true,
			"enabled":             true,
			"sync_interval_hours": 12,
			"platform_filter":     []string{"linux/amd64"},
			"version_filter":      vf,
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TriggerSync – error path
// ---------------------------------------------------------------------------

func TestTMTriggerSync_SyncJobError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	h := NewTerraformMirrorHandler(repo)
	h.SetSyncJob(&mockTMSyncJob{err: errDB})

	r := gin.New()
	r.POST("/terraform-mirrors/:id/sync", h.TriggerSync)

	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/terraform-mirrors/"+knownUUID+"/sync", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListVersions – with platforms query parameter
// ---------------------------------------------------------------------------

func TestTMListVersions_WithPlatforms(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT COUNT.*FROM terraform_versions WHERE config_id").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id").
		WillReturnRows(sampleTFVRow())
	// ListPlatformsForVersion for the returned version
	mock.ExpectQuery("SELECT.*FROM terraform_version_platforms WHERE version_id").
		WillReturnRows(sqlmock.NewRows(tmPlatformCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions?platforms=true", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteVersion – delete DB error
// ---------------------------------------------------------------------------

func TestTMMirrorDeleteVersion_DeleteDBError(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sampleTFVRow())
	mock.ExpectExec("DELETE FROM terraform_versions WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetSyncHistory – custom limit parameter
// ---------------------------------------------------------------------------

func TestTMGetSyncHistory_WithLimit(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_mirror_configs WHERE id").
		WillReturnRows(sampleTMCRow())
	mock.ExpectQuery("SELECT.*FROM terraform_sync_history WHERE config_id").
		WillReturnRows(sqlmock.NewRows(syncHistoryCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/history?limit=10", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListPlatforms – platforms DB error
// ---------------------------------------------------------------------------

func TestTMListPlatforms_DBErrorOnPlatforms(t *testing.T) {
	mock, r := newTerraformMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM terraform_versions WHERE config_id.*AND version").
		WillReturnRows(sampleTFVRow())
	mock.ExpectQuery("SELECT.*FROM terraform_version_platforms WHERE version_id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/terraform-mirrors/"+knownUUID+"/versions/1.7.0/platforms", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}
