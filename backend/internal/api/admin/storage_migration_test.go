package admin

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// ---------------------------------------------------------------------------
// Test setup helpers
// ---------------------------------------------------------------------------

// newMigrationHandler returns a StorageMigrationHandler backed by a nil service.
// Suitable for testing request validation that occurs before any service call.
func newMigrationHandler() *StorageMigrationHandler {
	return NewStorageMigrationHandler(nil)
}

// newMigrationRouter creates a gin router with all StorageMigrationHandler routes.
// The service is nil, so tests must only exercise paths that fail before calling the service.
func newMigrationRouter(t *testing.T) *gin.Engine {
	t.Helper()
	h := newMigrationHandler()
	r := gin.New()
	r.POST("/migrations/plan", h.PlanMigration)
	r.POST("/migrations", h.StartMigration)
	r.GET("/migrations", h.ListMigrations)
	r.GET("/migrations/:id", h.GetMigrationStatus)
	r.POST("/migrations/:id/cancel", h.CancelMigration)
	return r
}

// newMigrationRouterWithRecovery creates a gin router with gin.Recovery() middleware
// and a real (but infra-less) service, so panics from nil repos are caught as 500s.
func newMigrationRouterWithRecovery(t *testing.T) *gin.Engine {
	t.Helper()
	svc := services.NewStorageMigrationService(nil, nil, nil, nil, nil, nil)
	h := NewStorageMigrationHandler(svc)
	r := gin.New()
	r.Use(gin.Recovery())
	r.POST("/migrations/plan", h.PlanMigration)
	r.POST("/migrations", h.StartMigration)
	r.GET("/migrations", h.ListMigrations)
	r.GET("/migrations/:id", h.GetMigrationStatus)
	r.POST("/migrations/:id/cancel", h.CancelMigration)
	return r
}

// ---------------------------------------------------------------------------
// PlanMigration — request validation
// ---------------------------------------------------------------------------

func TestPlanMigration_InvalidJSON(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/plan", bytes.NewBufferString("{bad json")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestPlanMigration_EmptyBody(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/plan", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestPlanMigration_MissingSourceConfigID(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/plan",
		jsonBody(map[string]string{"target_config_id": "11111111-1111-1111-1111-111111111111"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestPlanMigration_MissingTargetConfigID(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/plan",
		jsonBody(map[string]string{"source_config_id": "11111111-1111-1111-1111-111111111111"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestPlanMigration_MissingBothFields(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/plan",
		jsonBody(map[string]string{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// StartMigration — request validation
// ---------------------------------------------------------------------------

func TestStartMigration_InvalidJSON(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations", bytes.NewBufferString("{bad")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestStartMigration_EmptyBody(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestStartMigration_MissingSourceConfigID(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations",
		jsonBody(map[string]string{"target_config_id": "11111111-1111-1111-1111-111111111111"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestStartMigration_MissingTargetConfigID(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations",
		jsonBody(map[string]string{"source_config_id": "11111111-1111-1111-1111-111111111111"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestStartMigration_MissingBothFields(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations",
		jsonBody(map[string]string{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetMigrationStatus — ID validation
// ---------------------------------------------------------------------------

func TestGetMigrationStatus_InvalidID(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	resp := getJSON(w)
	if resp["error"] != "invalid migration ID" {
		t.Errorf("error = %q, want 'invalid migration ID'", resp["error"])
	}
}

func TestGetMigrationStatus_EmptyID(t *testing.T) {
	r := newMigrationRouter(t)

	// The route pattern requires an :id param, so an empty segment gives 404 from the router
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations/", nil))

	// gin will 301 redirect or 404 depending on config; either way, not 200
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for empty ID path")
	}
}

// ---------------------------------------------------------------------------
// CancelMigration — ID validation
// ---------------------------------------------------------------------------

func TestCancelMigration_InvalidID(t *testing.T) {
	r := newMigrationRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/bad-id/cancel", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	resp := getJSON(w)
	if resp["error"] != "invalid migration ID" {
		t.Errorf("error = %q, want 'invalid migration ID'", resp["error"])
	}
}

// ---------------------------------------------------------------------------
// ListMigrations — pagination defaults (no service call needed — the handler
// parses query params before calling service, but with nil service it panics,
// so we test only with a real service that has nil repos → will fail on DB call)
// ---------------------------------------------------------------------------

func TestListMigrations_DefaultPagination(t *testing.T) {
	// ListMigrations calls service.ListMigrations which calls repo.ListMigrations.
	// With a nil repo, the service panics. gin.Recovery() converts it to a 500.
	// The key check: valid query params do NOT produce a 400 (validation is fine).
	r := newMigrationRouterWithRecovery(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations", nil))

	if w.Code == http.StatusBadRequest {
		t.Error("expected non-400 for valid request (should be 500 from nil repo)")
	}
}

func TestListMigrations_CustomPagination(t *testing.T) {
	r := newMigrationRouterWithRecovery(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations?limit=50&offset=10", nil))

	// Should not be 400; query params are valid
	if w.Code == http.StatusBadRequest {
		t.Error("expected non-400 for valid pagination params")
	}
}

func TestListMigrations_InvalidPaginationIgnored(t *testing.T) {
	r := newMigrationRouterWithRecovery(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations?limit=abc&offset=-1", nil))

	// Invalid values are silently clamped to defaults, so no 400
	if w.Code == http.StatusBadRequest {
		t.Error("expected non-400; invalid limit/offset should use defaults")
	}
}

// ---------------------------------------------------------------------------
// NewStorageMigrationHandler
// ---------------------------------------------------------------------------

func TestNewStorageMigrationHandler_NonNil(t *testing.T) {
	h := NewStorageMigrationHandler(nil)
	if h == nil {
		t.Fatal("NewStorageMigrationHandler returned nil")
	}
}

func TestNewStorageMigrationHandler_StoresService(t *testing.T) {
	svc := services.NewStorageMigrationService(nil, nil, nil, nil, nil, nil)
	h := NewStorageMigrationHandler(svc)
	if h == nil {
		t.Fatal("NewStorageMigrationHandler returned nil")
	}
	if h.service != svc {
		t.Error("service field was not set correctly")
	}
}

// ---------------------------------------------------------------------------
// Request struct validation — verify binding tags via gin context directly
// ---------------------------------------------------------------------------

func TestPlanRequest_BindingValidation(t *testing.T) {
	// Test that an empty JSON object fails binding for planRequest
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/", bytes.NewBufferString(`{}`))
	c.Request.Header.Set("Content-Type", "application/json")

	var req planRequest
	err := c.ShouldBindJSON(&req)
	if err == nil {
		t.Error("expected binding error for empty planRequest, got nil")
	}
}

func TestStartMigrationRequest_BindingValidation(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/", bytes.NewBufferString(`{}`))
	c.Request.Header.Set("Content-Type", "application/json")

	var req startMigrationRequest
	err := c.ShouldBindJSON(&req)
	if err == nil {
		t.Error("expected binding error for empty startMigrationRequest, got nil")
	}
}

func TestPlanRequest_ValidBinding(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"source_config_id":"src-123","target_config_id":"tgt-456"}`
	c.Request = httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")

	var req planRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		t.Fatalf("unexpected binding error: %v", err)
	}
	if req.SourceConfigID != "src-123" {
		t.Errorf("SourceConfigID = %q, want src-123", req.SourceConfigID)
	}
	if req.TargetConfigID != "tgt-456" {
		t.Errorf("TargetConfigID = %q, want tgt-456", req.TargetConfigID)
	}
}

func TestStartMigrationRequest_ValidBinding(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"source_config_id":"src-123","target_config_id":"tgt-456"}`
	c.Request = httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")

	var req startMigrationRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		t.Fatalf("unexpected binding error: %v", err)
	}
	if req.SourceConfigID != "src-123" {
		t.Errorf("SourceConfigID = %q, want src-123", req.SourceConfigID)
	}
	if req.TargetConfigID != "tgt-456" {
		t.Errorf("TargetConfigID = %q, want tgt-456", req.TargetConfigID)
	}
}

// ---------------------------------------------------------------------------
// Handler tests with sqlmock-backed service — full request/response paths
// ---------------------------------------------------------------------------

// migrationColumns matches the storage_migrations table columns for sqlmock rows.
var migrationColumns = []string{
	"id", "source_config_id", "target_config_id", "status",
	"total_artifacts", "migrated_artifacts", "failed_artifacts", "skipped_artifacts",
	"error_message", "started_at", "completed_at", "created_at", "created_by",
}

// newMockedMigrationRouter creates a router with a fully wired service backed by sqlmock.
// Returns the mock so the caller can set expectations.
func newMockedMigrationRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewStorageMigrationRepository(sqlxDB)
	scRepo := repositories.NewStorageConfigRepository(sqlxDB)
	svc := services.NewStorageMigrationService(repo, scRepo, nil, nil, nil, nil)
	h := NewStorageMigrationHandler(svc)

	r := gin.New()
	r.POST("/migrations/plan", h.PlanMigration)
	r.POST("/migrations", h.StartMigration)
	r.GET("/migrations", h.ListMigrations)
	r.GET("/migrations/:id", h.GetMigrationStatus)
	r.POST("/migrations/:id/cancel", h.CancelMigration)
	return mock, r
}

func TestGetMigrationStatus_Success(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)
	now := time.Now()

	migID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnRows(sqlmock.NewRows(migrationColumns).AddRow(
			migID, "src", "tgt", "running",
			10, 5, 0, 0,
			nil, nil, nil, now, nil,
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations/"+migID, nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestGetMigrationStatus_NotFound(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)

	migID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	// Return empty result set
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnRows(sqlmock.NewRows(migrationColumns))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations/"+migID, nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestCancelMigration_Success(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)
	now := time.Now()

	migID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// GetMigration returns a running migration
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnRows(sqlmock.NewRows(migrationColumns).AddRow(
			migID, "src", "tgt", "running",
			10, 5, 0, 0,
			nil, nil, nil, now, nil,
		))

	// UpdateMigrationStatus
	mock.ExpectExec("UPDATE storage_migrations SET status").
		WithArgs(migID, "cancelled", nil).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/"+migID+"/cancel", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestListMigrations_Success(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)
	now := time.Now()

	// Mock COUNT
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Mock SELECT
	mock.ExpectQuery("SELECT \\* FROM storage_migrations ORDER BY created_at DESC").
		WithArgs(20, 0).
		WillReturnRows(sqlmock.NewRows(migrationColumns).AddRow(
			"mig-1", "src", "tgt", "completed",
			5, 5, 0, 0,
			nil, nil, nil, now, nil,
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Handler tests — PlanMigration success & service error paths
// ---------------------------------------------------------------------------

// migStorageConfigRow builds a minimal row for storage_config with the given id and backend type.
func migStorageConfigRow(id, backendType string) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(storageConfigCols).AddRow(
		id, backendType, true,
		nil, nil, // local
		nil, nil, nil, nil, // azure
		nil, nil, nil, nil, // s3
		nil, nil,
		nil, nil, nil, nil, // s3 extra
		nil, nil, nil, nil, // gcs
		nil, nil,
		now, now, nil, nil, // metadata
	)
}

func TestPlanMigration_HandlerSuccess(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)

	srcID := "11111111-1111-1111-1111-111111111111"
	tgtID := "22222222-2222-2222-2222-222222222222"

	// GetStorageConfig for source
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(migStorageConfigRow(srcID, "local"))

	// GetStorageConfig for target
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(migStorageConfigRow(tgtID, "local"))

	// GetModuleArtifacts
	mock.ExpectQuery("SELECT id, storage_path FROM module_versions").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}).
			AddRow("mod-1", "/path/mod1"))

	// GetProviderArtifacts
	mock.ExpectQuery("SELECT id, storage_path FROM provider_platforms").
		WithArgs("local").
		WillReturnRows(sqlmock.NewRows([]string{"id", "storage_path"}))

	body := `{"source_config_id":"` + srcID + `","target_config_id":"` + tgtID + `"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/plan", bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("PlanMigration handler: status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestPlanMigration_ServiceError(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)

	srcID := "11111111-1111-1111-1111-111111111111"
	tgtID := "22222222-2222-2222-2222-222222222222"

	// Source config not found (empty result set)
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigCols))

	body := `{"source_config_id":"` + srcID + `","target_config_id":"` + tgtID + `"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/plan", bytes.NewBufferString(body)))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("PlanMigration service error: status = %d, want %d; body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
}

func TestStartMigration_HandlerServiceError(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)

	srcID := "11111111-1111-1111-1111-111111111111"
	tgtID := "22222222-2222-2222-2222-222222222222"

	// Source config not found
	mock.ExpectQuery("SELECT \\* FROM storage_config WHERE id").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(storageConfigCols))

	body := `{"source_config_id":"` + srcID + `","target_config_id":"` + tgtID + `"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations", bytes.NewBufferString(body)))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("StartMigration handler service error: status = %d, want %d; body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
}

func TestGetMigrationStatus_ServiceError(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)

	migID := "cccccccc-cccc-cccc-cccc-cccccccccccc"

	// DB error on the SELECT
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnError(fmt.Errorf("connection lost"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations/"+migID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("GetMigrationStatus service error: status = %d, want %d; body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
}

func TestListMigrations_ServiceError(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)

	// COUNT query fails
	mock.ExpectQuery("SELECT COUNT").
		WillReturnError(fmt.Errorf("db timeout"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/migrations", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("ListMigrations service error: status = %d, want %d; body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
}

func TestCancelMigration_ServiceError(t *testing.T) {
	mock, r := newMockedMigrationRouter(t)

	migID := "dddddddd-dddd-dddd-dddd-dddddddddddd"

	// GetMigration fails
	mock.ExpectQuery("SELECT \\* FROM storage_migrations WHERE id").
		WithArgs(migID).
		WillReturnError(fmt.Errorf("permission denied"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/migrations/"+migID+"/cancel", nil))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("CancelMigration service error: status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}
