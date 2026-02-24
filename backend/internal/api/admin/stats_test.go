package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newStatsRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	h := NewStatsHandler(sqlxDB)

	r := gin.New()
	r.GET("/stats/dashboard", h.GetDashboardStats)
	return mock, r
}

// expectStatsQueries sets up the full sequence of sqlmock expectations for a
// successful GetDashboardStats call, allowing callers to override individual
// row values.
func expectStatsQueries(mock sqlmock.Sqlmock, opts statsOpts) {
	// 1. Core counts
	coreCols := []string{
		"module_count", "module_version_count", "module_downloads",
		"provider_count", "provider_version_count", "provider_downloads",
		"user_count", "org_count",
	}
	mock.ExpectQuery("module_count").
		WillReturnRows(sqlmock.NewRows(coreCols).AddRow(
			opts.modules, opts.moduleVersions, opts.moduleDownloads,
			opts.providers, opts.providerVersions, opts.providerDownloads,
			opts.users, opts.orgs,
		))

	// 2. Mirrored provider counts
	mock.ExpectQuery("mirrored_providers").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(opts.mirroredProviders))
	mock.ExpectQuery("mirrored_provider_versions").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(opts.mirroredProviderVersions))
	mock.ExpectQuery("scm_providers").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(opts.scmProviders))

	// 3. Module breakdown by system
	sysRows := sqlmock.NewRows([]string{"system", "count"})
	for _, s := range opts.bySystem {
		sysRows.AddRow(s.System, s.Count)
	}
	mock.ExpectQuery("modules").WillReturnRows(sysRows)

	// 4. Binary mirror health
	binaryHealthCols := []string{"total", "healthy", "failed", "syncing"}
	mock.ExpectQuery("terraform_mirror_configs").
		WillReturnRows(sqlmock.NewRows(binaryHealthCols).AddRow(
			opts.binaryTotal, opts.binaryHealthy, opts.binaryFailed, opts.binarySyncing,
		))
	mock.ExpectQuery("terraform_version_platforms").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(opts.binaryPlatforms))
	mock.ExpectQuery("terraform_version_platforms").
		WillReturnRows(sqlmock.NewRows([]string{"sum"}).AddRow(opts.binaryDownloads))

	// 5. Per-tool platform breakdown
	toolRows := sqlmock.NewRows([]string{"tool", "platforms"})
	for _, t := range opts.byTool {
		toolRows.AddRow(t.Tool, t.Platforms)
	}
	mock.ExpectQuery("terraform_version_platforms").WillReturnRows(toolRows)

	// 6. Provider mirror health
	provHealthCols := []string{"total", "healthy", "failed"}
	mock.ExpectQuery("mirror_configurations").
		WillReturnRows(sqlmock.NewRows(provHealthCols).AddRow(
			opts.provMirrorTotal, opts.provMirrorHealthy, opts.provMirrorFailed,
		))

	// 7. Recent syncs
	recentCols := []string{
		"mirror_name", "mirror_type", "status", "started_at", "completed_at",
		"versions_synced", "platforms_synced", "triggered_by",
	}
	rows := sqlmock.NewRows(recentCols)
	for _, e := range opts.recentSyncs {
		rows.AddRow(e.MirrorName, e.MirrorType, e.Status, e.StartedAt, e.CompletedAt,
			e.VersionsSynced, e.PlatformsSynced, e.TriggeredBy)
	}
	mock.ExpectQuery("terraform_sync_history").WillReturnRows(rows)
}

type statsOpts struct {
	modules, moduleVersions, providers, providerVersions int64
	users, orgs                                          int64
	moduleDownloads, providerDownloads                   int64
	mirroredProviders                    int64
	mirroredProviderVersions             int64
	scmProviders                         int64
	binaryTotal, binaryHealthy, binaryFailed, binarySyncing int64
	binaryPlatforms, binaryDownloads                         int64
	provMirrorTotal, provMirrorHealthy, provMirrorFailed     int64
	bySystem                                                 []ModuleSystemCount
	byTool                                                   []BinaryToolCount
	recentSyncs                                              []RecentSyncEntry
}

func defaultStatsOpts() statsOpts {
	return statsOpts{
		modules: 10, moduleVersions: 25, providers: 5, providerVersions: 20,
		users: 15, orgs: 1,
		moduleDownloads: 100, providerDownloads: 200,
		mirroredProviders: 2, mirroredProviderVersions: 8,
		scmProviders:   3,
		binaryTotal:    2, binaryHealthy: 2, binaryFailed: 0, binarySyncing: 0,
		binaryPlatforms: 40,
		provMirrorTotal: 1, provMirrorHealthy: 1, provMirrorFailed: 0,
	}
}

// ---------------------------------------------------------------------------
// GetDashboardStats tests
// ---------------------------------------------------------------------------

func TestGetDashboardStats_Success(t *testing.T) {
	mock, r := newStatsRouter(t)
	expectStatsQueries(mock, defaultStatsOpts())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["modules"] == nil {
		t.Error("response missing 'modules' key")
	}
	if resp["providers"] == nil {
		t.Error("response missing 'providers' key")
	}
	if resp["binary_mirrors"] == nil {
		t.Error("response missing 'binary_mirrors' key")
	}
	if resp["provider_mirrors"] == nil {
		t.Error("response missing 'provider_mirrors' key")
	}
	if resp["recent_syncs"] == nil {
		t.Error("response missing 'recent_syncs' key")
	}
}

func TestGetDashboardStats_MirrorHealthValues(t *testing.T) {
	mock, r := newStatsRouter(t)

	opts := defaultStatsOpts()
	opts.binaryTotal = 3
	opts.binaryHealthy = 2
	opts.binaryFailed = 1
	opts.binaryPlatforms = 60
	opts.provMirrorTotal = 2
	opts.provMirrorFailed = 1

	expectStatsQueries(mock, opts)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	var body struct {
		BinaryMirrors struct {
			Total     int64 `json:"total"`
			Healthy   int64 `json:"healthy"`
			Failed    int64 `json:"failed"`
			Platforms int64 `json:"platforms"`
		} `json:"binary_mirrors"`
		ProviderMirrors struct {
			Total  int64 `json:"total"`
			Failed int64 `json:"failed"`
		} `json:"provider_mirrors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if body.BinaryMirrors.Total != 3 {
		t.Errorf("binary_mirrors.total = %d, want 3", body.BinaryMirrors.Total)
	}
	if body.BinaryMirrors.Failed != 1 {
		t.Errorf("binary_mirrors.failed = %d, want 1", body.BinaryMirrors.Failed)
	}
	if body.BinaryMirrors.Platforms != 60 {
		t.Errorf("binary_mirrors.platforms = %d, want 60", body.BinaryMirrors.Platforms)
	}
	if body.ProviderMirrors.Total != 2 {
		t.Errorf("provider_mirrors.total = %d, want 2", body.ProviderMirrors.Total)
	}
	if body.ProviderMirrors.Failed != 1 {
		t.Errorf("provider_mirrors.failed = %d, want 1", body.ProviderMirrors.Failed)
	}
}

func TestGetDashboardStats_RecentSyncs(t *testing.T) {
	mock, r := newStatsRouter(t)

	now := time.Now().UTC().Truncate(time.Second)
	opts := defaultStatsOpts()
	opts.recentSyncs = []RecentSyncEntry{
		{
			MirrorName: "hashicorp-terraform", MirrorType: "binary",
			Status: "success", StartedAt: now, VersionsSynced: 2, PlatformsSynced: 8,
			TriggeredBy: "manual",
		},
		{
			MirrorName: "registry.terraform.io", MirrorType: "provider",
			Status: "success", StartedAt: now.Add(-5 * time.Minute), VersionsSynced: 5,
			TriggeredBy: "scheduler",
		},
	}
	expectStatsQueries(mock, opts)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}

	var body struct {
		RecentSyncs []RecentSyncEntry `json:"recent_syncs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if len(body.RecentSyncs) != 2 {
		t.Errorf("recent_syncs len = %d, want 2", len(body.RecentSyncs))
	}
	if body.RecentSyncs[0].MirrorName != "hashicorp-terraform" {
		t.Errorf("first sync mirror_name = %q, want %q", body.RecentSyncs[0].MirrorName, "hashicorp-terraform")
	}
	if body.RecentSyncs[0].MirrorType != "binary" {
		t.Errorf("first sync mirror_type = %q, want %q", body.RecentSyncs[0].MirrorType, "binary")
	}
	if body.RecentSyncs[1].MirrorType != "provider" {
		t.Errorf("second sync mirror_type = %q, want %q", body.RecentSyncs[1].MirrorType, "provider")
	}
}

func TestGetDashboardStats_RecentSyncsEmpty(t *testing.T) {
	mock, r := newStatsRouter(t)

	opts := defaultStatsOpts()
	// No recent syncs — result must be [] not null
	expectStatsQueries(mock, opts)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body struct {
		RecentSyncs []RecentSyncEntry `json:"recent_syncs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if body.RecentSyncs == nil {
		t.Error("recent_syncs must be [] not null when empty")
	}
}

func TestGetDashboardStats_OptionalQueriesFail(t *testing.T) {
	// When optional mirror tables return errors, the handler still returns 200
	// with the core stats and zero values for the optional fields.
	mock, r := newStatsRouter(t)

	coreCols := []string{
		"module_count", "module_version_count", "module_downloads",
		"provider_count", "provider_version_count", "provider_downloads",
		"user_count", "org_count",
	}
	mock.ExpectQuery("module_count").
		WillReturnRows(sqlmock.NewRows(coreCols).AddRow(
			int64(10), int64(25), int64(100), int64(5), int64(20), int64(200), int64(15), int64(1),
		))
	// All optional queries fail — handler ignores errors via _ = ...
	mock.ExpectQuery("mirrored_providers").WillReturnError(errDB)
	mock.ExpectQuery("mirrored_provider_versions").WillReturnError(errDB)
	mock.ExpectQuery("scm_providers").WillReturnError(errDB)
	mock.ExpectQuery("modules").WillReturnError(errDB)            // by-system breakdown
	mock.ExpectQuery("terraform_mirror_configs").WillReturnError(errDB)
	mock.ExpectQuery("terraform_version_platforms").WillReturnError(errDB) // platform count
	mock.ExpectQuery("terraform_version_platforms").WillReturnError(errDB) // binary downloads
	mock.ExpectQuery("terraform_version_platforms").WillReturnError(errDB) // by-tool breakdown
	mock.ExpectQuery("mirror_configurations").WillReturnError(errDB)
	mock.ExpectQuery("terraform_sync_history").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 even when optional queries fail: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["modules"] == nil {
		t.Error("response missing 'modules' key")
	}
}

func TestGetDashboardStats_CoreQueryFails(t *testing.T) {
	mock, r := newStatsRouter(t)

	mock.ExpectQuery("module_count").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestGetDashboardStats_DownloadAggregation(t *testing.T) {
	mock, r := newStatsRouter(t)

	opts := defaultStatsOpts()
	opts.moduleDownloads = 150
	opts.providerDownloads = 350
	expectStatsQueries(mock, opts)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body struct {
		Downloads int64 `json:"downloads"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if body.Downloads != 500 {
		t.Errorf("downloads = %d, want 500 (150+350)", body.Downloads)
	}
}

func TestGetDashboardStats_ProviderMirrorBreakdown(t *testing.T) {
	mock, r := newStatsRouter(t)

	opts := defaultStatsOpts()
	opts.providers = 10
	opts.providerVersions = 30
	opts.mirroredProviders = 4
	opts.mirroredProviderVersions = 12
	expectStatsQueries(mock, opts)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/stats/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body struct {
		Providers struct {
			Total          int64 `json:"total"`
			Manual         int64 `json:"manual"`
			Mirrored       int64 `json:"mirrored"`
			ManualVersions int64 `json:"manual_versions"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if body.Providers.Manual != 6 {
		t.Errorf("providers.manual = %d, want 6 (10-4)", body.Providers.Manual)
	}
	if body.Providers.ManualVersions != 18 {
		t.Errorf("providers.manual_versions = %d, want 18 (30-12)", body.Providers.ManualVersions)
	}
}
