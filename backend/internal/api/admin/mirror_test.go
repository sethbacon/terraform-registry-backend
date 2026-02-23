package admin

import (
	"context"
	"fmt"
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

var mirrorCfgCols = []string{
	"id", "name", "description", "upstream_registry_url", "organization_id",
	"namespace_filter", "provider_filter", "version_filter", "platform_filter",
	"enabled", "sync_interval_hours", "last_sync_at", "last_sync_status", "last_sync_error",
	"created_at", "updated_at", "created_by",
}

var mirrorSyncHistCols = []string{
	"id", "mirror_config_id", "started_at", "completed_at", "status",
	"providers_synced", "providers_failed", "error_message", "sync_details",
}

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleMirrorCfgRow() *sqlmock.Rows {
	return sqlmock.NewRows(mirrorCfgCols).AddRow(
		knownUUID, "test-mirror", nil, "https://registry.terraform.io", nil,
		nil, nil, nil, nil,
		true, 24, nil, nil, nil,
		time.Now(), time.Now(), nil,
	)
}

func emptySyncHistRows() *sqlmock.Rows {
	return sqlmock.NewRows(mirrorSyncHistCols)
}

// ---------------------------------------------------------------------------
// Mock sync job
// ---------------------------------------------------------------------------

type mockSyncJob struct {
	err error
}

func (m *mockSyncJob) TriggerManualSync(_ context.Context, _ uuid.UUID) error {
	return m.err
}

// ---------------------------------------------------------------------------
// Router helpers
// ---------------------------------------------------------------------------

func newMirrorRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	return newMirrorRouterWithJob(t, nil)
}

func newMirrorRouterWithJob(t *testing.T, syncJob MirrorSyncJobInterface) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	mirrorRepo := repositories.NewMirrorRepository(sqlxDB)
	h := NewMirrorHandler(mirrorRepo)
	if syncJob != nil {
		h.SetSyncJob(syncJob)
	}

	r := gin.New()
	r.POST("/mirrors", h.CreateMirrorConfig)
	r.GET("/mirrors", h.ListMirrorConfigs)
	r.GET("/mirrors/:id", h.GetMirrorConfig)
	r.PUT("/mirrors/:id", h.UpdateMirrorConfig)
	r.DELETE("/mirrors/:id", h.DeleteMirrorConfig)
	r.POST("/mirrors/:id/sync", h.TriggerSync)
	r.GET("/mirrors/:id/status", h.GetMirrorStatus)
	return mock, r
}

// ---------------------------------------------------------------------------
// CreateMirrorConfig
// ---------------------------------------------------------------------------

func TestMirrorCreate_MissingBody(t *testing.T) {
	_, r := newMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{}))) // missing required name + upstream_registry_url

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorCreate_NameConflict(t *testing.T) {
	mock, r := newMirrorRouter(t)
	// GetByName returns existing row
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnRows(sampleMirrorCfgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{
			"name":                  "test-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
		})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorCreate_GetByNameDBError(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{
			"name":                  "new-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestMirrorCreate_Success(t *testing.T) {
	mock, r := newMirrorRouter(t)
	// GetByName returns no rows (name available)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))
	// INSERT
	mock.ExpectExec("INSERT INTO mirror_configurations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{
			"name":                  "new-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorCreate_InsertDBError(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))
	mock.ExpectExec("INSERT INTO mirror_configurations").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{
			"name":                  "new-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ListMirrorConfigs
// ---------------------------------------------------------------------------

func TestMirrorList_Empty(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/mirrors", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if _, ok := resp["mirrors"]; !ok {
		t.Error("response missing 'mirrors' key")
	}
}

func TestMirrorList_DBError(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/mirrors", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetMirrorConfig
// ---------------------------------------------------------------------------

func TestMirrorGetByID_InvalidID(t *testing.T) {
	_, r := newMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/mirrors/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestMirrorGetByID_NotFound(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/mirrors/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestMirrorGetByID_DBError(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/mirrors/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestMirrorGetByID_Success(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/mirrors/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateMirrorConfig
// ---------------------------------------------------------------------------

func TestMirrorUpdate_InvalidID(t *testing.T) {
	_, r := newMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/not-a-uuid",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestMirrorUpdate_NotFound(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))

	enabled := false
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"enabled": &enabled})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestMirrorUpdate_Success(t *testing.T) {
	mock, r := newMirrorRouter(t)
	// GetByID returns existing config
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	// UPDATE
	mock.ExpectExec("UPDATE mirror_configurations SET name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	enabled := false
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"enabled": &enabled})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteMirrorConfig
// ---------------------------------------------------------------------------

func TestMirrorDelete_InvalidID(t *testing.T) {
	_, r := newMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/mirrors/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestMirrorDelete_NotFound(t *testing.T) {
	mock, r := newMirrorRouter(t)
	// 0 rows affected → repo returns error → handler returns 500
	mock.ExpectExec("DELETE FROM mirror_configurations WHERE id").
		WillReturnResult(sqlmock.NewResult(0, 0))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/mirrors/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestMirrorDelete_DBError(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectExec("DELETE FROM mirror_configurations WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/mirrors/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestMirrorDelete_Success(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectExec("DELETE FROM mirror_configurations WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/mirrors/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TriggerSync
// ---------------------------------------------------------------------------

func TestMirrorTriggerSync_InvalidID(t *testing.T) {
	_, r := newMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors/not-a-uuid/sync", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestMirrorTriggerSync_NotFound(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors/"+knownUUID+"/sync", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestMirrorTriggerSync_NoJob(t *testing.T) {
	// syncJob = nil → 503
	mock, r := newMirrorRouter(t) // nil syncJob by default
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors/"+knownUUID+"/sync", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestMirrorTriggerSync_Success(t *testing.T) {
	mock, r := newMirrorRouterWithJob(t, &mockSyncJob{err: nil})
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors/"+knownUUID+"/sync", nil))

	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorTriggerSync_AlreadyInProgress(t *testing.T) {
	mock, r := newMirrorRouterWithJob(t, &mockSyncJob{
		err: fmt.Errorf("sync already in progress for this mirror"),
	})
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors/"+knownUUID+"/sync", nil))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetMirrorStatus
// ---------------------------------------------------------------------------

func TestMirrorGetStatus_InvalidID(t *testing.T) {
	_, r := newMirrorRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/mirrors/not-a-uuid/status", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestMirrorGetStatus_NotFound(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/mirrors/"+knownUUID+"/status", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestMirrorGetStatus_Success(t *testing.T) {
	mock, r := newMirrorRouter(t)
	// GetByID
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	// GetActiveSyncHistory (uses GetContext → returns empty → nil)
	mock.ExpectQuery("SELECT.*FROM mirror_sync_history WHERE mirror_config_id.*AND status").
		WillReturnRows(emptySyncHistRows())
	// GetSyncHistory (uses SelectContext)
	mock.ExpectQuery("SELECT.*FROM mirror_sync_history WHERE mirror_config_id").
		WillReturnRows(emptySyncHistRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/mirrors/"+knownUUID+"/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["mirror_config"] == nil {
		t.Error("response missing 'mirror_config' key")
	}
}

// ---------------------------------------------------------------------------
// UpdateMirrorConfig — additional paths
// ---------------------------------------------------------------------------

func TestMirrorUpdate_GetByIDDBError(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"enabled": false})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorUpdate_NameConflict(t *testing.T) {
	mock, r := newMirrorRouter(t)
	// GetByID returns "test-mirror"
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	// GetByName for new name returns an existing config → conflict
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnRows(sampleMirrorCfgRow())

	newName := "conflict-name"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"name": &newName})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorUpdate_GetByNameDBError(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	// GetByName fails
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnError(errDB)

	newName := "new-mirror-name"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"name": &newName})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorUpdate_UpdateDBError(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	mock.ExpectExec("UPDATE mirror_configurations SET name").
		WillReturnError(errDB)

	enabled := true
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"enabled": &enabled})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorUpdate_InvalidRegistryURL(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())

	badURL := "not-a-valid-url"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"upstream_registry_url": &badURL})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateMirrorConfig — additional paths
// ---------------------------------------------------------------------------

func TestMirrorCreate_WithFiltersAndCustomInterval(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))
	mock.ExpectExec("INSERT INTO mirror_configurations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	interval := 6
	enabled := false
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{
			"name":                  "filtered-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
			"namespace_filter":      []string{"hashicorp", "aws"},
			"provider_filter":       []string{"aws", "azurerm"},
			"platform_filter":       []string{"linux_amd64"},
			"sync_interval_hours":   interval,
			"enabled":               enabled,
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorCreate_WithValidOrgID(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))
	mock.ExpectExec("INSERT INTO mirror_configurations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	orgID := knownUUID
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{
			"name":                  "org-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
			"organization_id":       orgID,
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorCreate_InvalidOrgID(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))

	badOrgID := "not-a-uuid"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{
			"name":                  "bad-org-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
			"organization_id":       badOrgID,
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorCreate_WithUserIDContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	mirrorRepo := repositories.NewMirrorRepository(sqlxDB)
	h := NewMirrorHandler(mirrorRepo)

	r := gin.New()
	// Inject user_id as uuid.UUID into context before the handler
	userUUID := uuid.MustParse(knownUUID)
	r.POST("/mirrors", func(c *gin.Context) {
		c.Set("user_id", userUUID)
		h.CreateMirrorConfig(c)
	})

	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE name").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols))
	mock.ExpectExec("INSERT INTO mirror_configurations").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/mirrors",
		jsonBody(map[string]interface{}{
			"name":                  "user-mirror",
			"upstream_registry_url": "https://registry.terraform.io",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateMirrorConfig — additional filter/field paths
// ---------------------------------------------------------------------------

func TestMirrorUpdate_WithFiltersAndInterval(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	mock.ExpectExec("UPDATE mirror_configurations SET name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	versionFilter := ">=1.0.0"
	interval := 12
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{
			"namespace_filter":    []string{"hashicorp"},
			"provider_filter":     []string{"aws"},
			"platform_filter":     []string{"linux_amd64", "darwin_amd64"},
			"version_filter":      versionFilter,
			"sync_interval_hours": interval,
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorUpdate_ClearFilters(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	mock.ExpectExec("UPDATE mirror_configurations SET name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	emptyVersionFilter := ""
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{
			"namespace_filter": []string{},
			"provider_filter":  []string{},
			"platform_filter":  []string{},
			"version_filter":   emptyVersionFilter,
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorUpdate_SetOrganizationID(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	mock.ExpectExec("UPDATE mirror_configurations SET name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	orgID := knownUUID
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"organization_id": orgID})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorUpdate_ClearOrganizationID(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	mock.ExpectExec("UPDATE mirror_configurations SET name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	emptyOrgID := ""
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"organization_id": emptyOrgID})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorUpdate_InvalidOrganizationID(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())

	badOrgID := "not-a-uuid"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"organization_id": badOrgID})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestMirrorUpdate_Description(t *testing.T) {
	mock, r := newMirrorRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations WHERE id").
		WillReturnRows(sampleMirrorCfgRow())
	mock.ExpectExec("UPDATE mirror_configurations SET name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	desc := "updated description"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/mirrors/"+knownUUID,
		jsonBody(map[string]interface{}{"description": desc})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}
