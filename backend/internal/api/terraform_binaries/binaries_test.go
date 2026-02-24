package terraform_binaries

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// ---- constants & shared test data -------------------------------------------

const (
	sampleConfigID   = "cccccccc-0000-0000-0000-000000000001"
	sampleConfigName = "hashicorp-terraform"
	sampleVersionID  = "aaaaaaaa-0000-0000-0000-000000000001"
	samplePlatformID = "bbbbbbbb-0000-0000-0000-000000000001"
)

var configCols = []string{
	"id", "name", "description", "tool", "enabled", "upstream_url",
	"platform_filter", "version_filter", "gpg_verify", "stable_only", "sync_interval_hours",
	"last_sync_at", "last_sync_status", "last_sync_error",
	"created_at", "updated_at",
}

var versionCols = []string{
	"id", "config_id", "version", "is_latest", "is_deprecated", "release_date",
	"sync_status", "sync_error", "synced_at", "created_at", "updated_at",
}

var platformCols = []string{
	"id", "version_id", "os", "arch", "upstream_url", "filename", "sha256",
	"storage_key", "storage_backend", "sha256_verified", "gpg_verified",
	"sync_status", "sync_error", "synced_at", "created_at", "updated_at",
}

func sampleConfigRow() *sqlmock.Rows {
	upstream := "https://releases.hashicorp.com"
	return sqlmock.NewRows(configCols).AddRow(
		sampleConfigID, sampleConfigName, nil, "terraform", true,
		upstream, nil, nil, true, false, 24,
		nil, nil, nil,
		time.Now(), time.Now(),
	)
}

func sampleVersionRow(version string, isLatest bool) *sqlmock.Rows {
	return sqlmock.NewRows(versionCols).AddRow(
		sampleVersionID, sampleConfigID, version, isLatest, false, nil,
		"synced", nil, time.Now(), time.Now(), time.Now(),
	)
}

func samplePlatformRow(storageKey string) *sqlmock.Rows {
	sk := storageKey
	backend := "s3"
	return sqlmock.NewRows(platformCols).AddRow(
		samplePlatformID, sampleVersionID, "linux", "amd64",
		"https://releases.hashicorp.com/terraform/1.9.0/terraform_1.9.0_linux_amd64.zip",
		"terraform_1.9.0_linux_amd64.zip",
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		&sk, &backend, true, true,
		"synced", nil, time.Now(), time.Now(), time.Now(),
	)
}

// ---- mock storage -----------------------------------------------------------

type mockStorage struct {
	url string
	err error
}

func (m *mockStorage) Upload(_ context.Context, _ string, _ io.Reader, _ int64) (*storage.UploadResult, error) {
	return &storage.UploadResult{}, nil
}
func (m *mockStorage) Download(_ context.Context, _ string) (io.ReadCloser, error) { return nil, nil }
func (m *mockStorage) Delete(_ context.Context, _ string) error                    { return nil }
func (m *mockStorage) Exists(_ context.Context, _ string) (bool, error)            { return true, nil }
func (m *mockStorage) GetMetadata(_ context.Context, _ string) (*storage.FileMetadata, error) {
	return &storage.FileMetadata{}, nil
}
func (m *mockStorage) GetURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return m.url, m.err
}

// ---- router helper ----------------------------------------------------------

func newRouter(t *testing.T, store storage.Storage) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "postgres")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)

	if store == nil {
		store = &mockStorage{url: "https://example.com/download"}
	}

	h := NewHandler(repo, store)
	r := gin.New()
	r.GET("/:name/versions", h.ListVersions)
	r.GET("/:name/versions/latest", h.GetLatestVersion)
	r.GET("/:name/versions/:version", h.GetVersion)
	r.GET("/:name/versions/:version/:os/:arch", h.DownloadBinary)

	return mock, r
}

// ---- ListVersions -----------------------------------------------------------

func TestListVersions_Success(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id`).
		WithArgs(sampleConfigID).
		WillReturnRows(sampleVersionRow("1.9.0", true))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.EqualValues(t, 1, resp["total_count"])
}

func TestListVersions_MirrorNotFound(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs("unknown-mirror").
		WillReturnError(sql.ErrNoRows)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/unknown-mirror/versions", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListVersions_MirrorDisabled(t *testing.T) {
	mock, r := newRouter(t, nil)

	upstream := "https://releases.hashicorp.com"
	disabledRow := sqlmock.NewRows(configCols).AddRow(
		sampleConfigID, sampleConfigName, nil, "terraform", false, /* enabled=false */
		upstream, nil, nil, true, false, 24, nil, nil, nil, time.Now(), time.Now(),
	)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(disabledRow)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListVersions_DBError(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id`).
		WithArgs(sampleConfigID).
		WillReturnError(sql.ErrConnDone)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---- GetLatestVersion -------------------------------------------------------

func TestGetLatestVersion_Success(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*is_latest`).
		WithArgs(sampleConfigID).
		WillReturnRows(sampleVersionRow("1.9.0", true))

	// ListPlatformsForVersion
	mock.ExpectQuery(`SELECT.*FROM terraform_version_platforms.*WHERE version_id`).
		WithArgs(sampleVersionID).
		WillReturnRows(sqlmock.NewRows(platformCols))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/latest", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "1.9.0", resp["version"])
}

func TestGetLatestVersion_NoLatest(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*is_latest`).
		WithArgs(sampleConfigID).
		WillReturnError(sql.ErrNoRows)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/latest", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---- GetVersion -------------------------------------------------------------

func TestGetVersion_Success(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnRows(sampleVersionRow("1.9.0", false))

	mock.ExpectQuery(`SELECT.*FROM terraform_version_platforms.*WHERE version_id`).
		WithArgs(sampleVersionID).
		WillReturnRows(samplePlatformRow("tf/1.9.0/linux_amd64.zip"))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "1.9.0", resp["version"])
}

func TestGetVersion_InvalidSemver(t *testing.T) {
	_, r := newRouter(t, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/not-a-version", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetVersion_VersionNotFound(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "9.9.9").
		WillReturnError(sql.ErrNoRows)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/9.9.9", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetVersion_PendingVersion(t *testing.T) {
	mock, r := newRouter(t, nil)

	pendingRow := sqlmock.NewRows(versionCols).AddRow(
		sampleVersionID, sampleConfigID, "1.9.0", false, false, nil,
		"pending", nil, nil, time.Now(), time.Now(),
	)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnRows(pendingRow)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---- DownloadBinary ---------------------------------------------------------

func TestDownloadBinary_Success(t *testing.T) {
	store := &mockStorage{url: "https://example.com/signed-download-url"}
	mock, r := newRouter(t, store)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnRows(sampleVersionRow("1.9.0", true))

	mock.ExpectQuery(`SELECT.*FROM terraform_version_platforms.*WHERE version_id.*os.*arch`).
		WithArgs(sampleVersionID, "linux", "amd64").
		WillReturnRows(samplePlatformRow("tf/1.9.0/linux_amd64.zip"))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0/linux/amd64", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "https://example.com/signed-download-url", resp["download_url"])
	assert.Equal(t, "linux", resp["os"])
	assert.Equal(t, "amd64", resp["arch"])
}

func TestDownloadBinary_InvalidVersion(t *testing.T) {
	_, r := newRouter(t, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/bad-version/linux/amd64", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDownloadBinary_InvalidPlatform(t *testing.T) {
	_, r := newRouter(t, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0/haiku/m68k", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDownloadBinary_VersionNotFound(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnError(sql.ErrNoRows)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0/linux/amd64", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDownloadBinary_PlatformNotFound(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnRows(sampleVersionRow("1.9.0", true))

	mock.ExpectQuery(`SELECT.*FROM terraform_version_platforms.*WHERE version_id.*os.*arch`).
		WithArgs(sampleVersionID, "windows", "amd64").
		WillReturnError(sql.ErrNoRows)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0/windows/amd64", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDownloadBinary_PlatformPending(t *testing.T) {
	mock, r := newRouter(t, nil)

	pendingPlatformRow := sqlmock.NewRows(platformCols).AddRow(
		samplePlatformID, sampleVersionID, "linux", "amd64",
		"https://upstream-url",
		"terraform_1.9.0_linux_amd64.zip",
		"abcdef1234",
		nil, nil, false, false,
		"pending", nil, nil, time.Now(), time.Now(),
	)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnRows(sampleVersionRow("1.9.0", true))

	mock.ExpectQuery(`SELECT.*FROM terraform_version_platforms.*WHERE version_id.*os.*arch`).
		WithArgs(sampleVersionID, "linux", "amd64").
		WillReturnRows(pendingPlatformRow)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0/linux/amd64", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// ---- ListConfigs ------------------------------------------------------------

// newListConfigsRouter registers the ListConfigs handler at GET / for isolated testing.
func newListConfigsRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "postgres")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)

	h := NewHandler(repo, &mockStorage{url: "https://example.com/download"})
	r := gin.New()
	r.GET("/", h.ListConfigs)
	return mock, r
}

func TestListConfigs_Success_Empty(t *testing.T) {
	mock, r := newListConfigsRouter(t)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE enabled`).
		WillReturnRows(sqlmock.NewRows(configCols))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp, 0)
}

func TestListConfigs_Success_WithItems(t *testing.T) {
	mock, r := newListConfigsRouter(t)

	desc := "My mirror"
	rows := sqlmock.NewRows(configCols).AddRow(
		sampleConfigID, sampleConfigName, &desc, "terraform", true,
		"https://releases.hashicorp.com", nil, nil, true, false, 24,
		nil, nil, nil,
		time.Now(), time.Now(),
	)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE enabled`).
		WillReturnRows(rows)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp, 1)
	assert.Equal(t, sampleConfigName, resp[0]["name"])
	assert.Equal(t, "terraform", resp[0]["tool"])
	assert.Equal(t, "My mirror", resp[0]["description"])
}

func TestListConfigs_DBError(t *testing.T) {
	mock, r := newListConfigsRouter(t)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE enabled`).
		WillReturnError(sql.ErrConnDone)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---- ResolveConfig error paths ----------------------------------------------

func TestResolveConfig_GetByNameDBError(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnError(sql.ErrConnDone)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---- GetLatestVersion additional error paths --------------------------------

func TestGetLatestVersion_DBError(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*is_latest`).
		WithArgs(sampleConfigID).
		WillReturnError(sql.ErrConnDone)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/latest", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---- GetVersion additional error paths -------------------------------------

func TestGetVersion_DBError(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnError(sql.ErrConnDone)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---- DownloadBinary additional error paths ----------------------------------

func TestDownloadBinary_VersionDBError(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnError(sql.ErrConnDone)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0/linux/amd64", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDownloadBinary_PlatformDBError(t *testing.T) {
	mock, r := newRouter(t, nil)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnRows(sampleVersionRow("1.9.0", true))

	mock.ExpectQuery(`SELECT.*FROM terraform_version_platforms.*WHERE version_id.*os.*arch`).
		WithArgs(sampleVersionID, "linux", "amd64").
		WillReturnError(sql.ErrConnDone)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0/linux/amd64", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDownloadBinary_StorageURLError(t *testing.T) {
	store := &mockStorage{url: "", err: sql.ErrConnDone}
	mock, r := newRouter(t, store)

	mock.ExpectQuery(`SELECT.*FROM terraform_mirror_configs.*WHERE name`).
		WithArgs(sampleConfigName).
		WillReturnRows(sampleConfigRow())

	mock.ExpectQuery(`SELECT.*FROM terraform_versions.*WHERE config_id.*version`).
		WithArgs(sampleConfigID, "1.9.0").
		WillReturnRows(sampleVersionRow("1.9.0", true))

	mock.ExpectQuery(`SELECT.*FROM terraform_version_platforms.*WHERE version_id.*os.*arch`).
		WithArgs(sampleVersionID, "linux", "amd64").
		WillReturnRows(samplePlatformRow("tf/1.9.0/linux_amd64.zip"))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sampleConfigName+"/versions/1.9.0/linux/amd64", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
