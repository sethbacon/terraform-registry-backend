package jobs

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeVersions(vs ...string) []mirror.ProviderVersion {
	out := make([]mirror.ProviderVersion, len(vs))
	for i, v := range vs {
		out[i] = mirror.ProviderVersion{Version: v, Protocols: []string{"6.0"}}
	}
	return out
}

func versionNames(versions []mirror.ProviderVersion) []string {
	out := make([]string, len(versions))
	for i, v := range versions {
		out[i] = v.Version
	}
	return out
}

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// safeString
// ---------------------------------------------------------------------------

func TestSafeString_Nil(t *testing.T) {
	if got := safeString(nil); got != "(none)" {
		t.Errorf("safeString(nil) = %q, want (none)", got)
	}
}

func TestSafeString_NonNil(t *testing.T) {
	s := "hello"
	if got := safeString(&s); got != "hello" {
		t.Errorf("safeString(&%q) = %q, want hello", s, got)
	}
}

// ---------------------------------------------------------------------------
// mirror.CompareSemver (covers parseSemverParts behaviour indirectly)
// ---------------------------------------------------------------------------

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.1.0", "1.0.9", 1},
		{"1.0.0-alpha", "1.0.0", 0}, // pre-release stripped → equal
		{"3.74.0", "3.73.0", 1},
		// parseSemverParts edge cases exercised here:
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0}, // missing patch treated as 0
		{"1", "1.0.0", 0},   // only major
		{"abc", "0.0.0", 0}, // non-numeric → 0
	}
	for _, tt := range tests {
		got := mirror.CompareSemver(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("mirror.CompareSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// parseSHASUMFile
// ---------------------------------------------------------------------------

func TestParseSHASUMFile_Valid(t *testing.T) {
	content := `abc123  terraform-provider-aws_5.0.0_linux_amd64.zip
def456  terraform-provider-aws_5.0.0_darwin_arm64.zip
`
	result := parseSHASUMFile(content)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}
	if result["terraform-provider-aws_5.0.0_linux_amd64.zip"] != "abc123" {
		t.Errorf("linux/amd64 checksum = %q", result["terraform-provider-aws_5.0.0_linux_amd64.zip"])
	}
	if result["terraform-provider-aws_5.0.0_darwin_arm64.zip"] != "def456" {
		t.Errorf("darwin/arm64 checksum = %q", result["terraform-provider-aws_5.0.0_darwin_arm64.zip"])
	}
}

func TestParseSHASUMFile_Empty(t *testing.T) {
	result := parseSHASUMFile("")
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

func TestParseSHASUMFile_SkipsMalformedLines(t *testing.T) {
	// Lines without double-space separator are skipped
	content := "singlespaceonly nodoublespace\nabc123  valid-file.zip\n\n"
	result := parseSHASUMFile(content)
	if len(result) != 1 {
		t.Errorf("expected 1 valid entry, got %d: %v", len(result), result)
	}
}

func TestParseSHASUMFile_EmptyLines(t *testing.T) {
	content := "\n\n\n"
	result := parseSHASUMFile(content)
	if len(result) != 0 {
		t.Errorf("expected empty map for blank content, got %d entries", len(result))
	}
}

// ---------------------------------------------------------------------------
// mirror.FilterVersions — exercises prefix, list, semver, latest sub-filters
// ---------------------------------------------------------------------------

func TestFilterVersionsByPrefix(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0", "2.0.0", "4.0.0")
	got := mirror.FilterVersions(versions, strPtr("3."))
	if len(got) != 2 {
		t.Errorf("expected 2 versions with prefix 3., got %d: %v", len(got), versionNames(got))
	}
}

func TestFilterVersionsByPrefix_NoMatch(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0")
	got := mirror.FilterVersions(versions, strPtr("5."))
	if len(got) != 0 {
		t.Errorf("expected empty, got %d", len(got))
	}
}

func TestFilterVersionsByList(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0", "2.0.0", "4.0.0")
	got := mirror.FilterVersions(versions, strPtr("3.74.0,2.0.0"))
	if len(got) != 2 {
		t.Errorf("expected 2, got %d: %v", len(got), versionNames(got))
	}
}

func TestFilterVersionsByList_WithSpaces(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := mirror.FilterVersions(versions, strPtr(" 1.0.0 , 2.0.0 "))
	if len(got) != 2 {
		t.Errorf("expected 2, got %d", len(got))
	}
}

func TestFilterVersionsByList_NoMatch(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := mirror.FilterVersions(versions, strPtr("9.9.9"))
	if len(got) != 0 {
		t.Errorf("expected empty, got %d", len(got))
	}
}

func TestFilterVersionsBySemverConstraint(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0", "4.0.0")
	tests := []struct {
		constraint string
		wantCount  int
	}{
		{">=3.0.0", 2},
		{">3.0.0", 1},
		{"<=2.0.0", 2},
		{"<2.0.0", 1},
	}
	for _, tt := range tests {
		got := mirror.FilterVersions(versions, strPtr(tt.constraint))
		if len(got) != tt.wantCount {
			t.Errorf("FilterVersions(%q) = len %d, want %d", tt.constraint, len(got), tt.wantCount)
		}
	}
}

func TestFilterVersionsBySemverConstraint_NoOp(t *testing.T) {
	// "~>1.0" is not a recognized operator prefix, prefix suffix, list, or semver constraint.
	// FilterVersions falls through to exact-list matching, finds no match, returns empty.
	versions := makeVersions("1.0.0", "2.0.0")
	got := mirror.FilterVersions(versions, strPtr("~>1.0"))
	if len(got) != 0 {
		t.Errorf("unrecognized constraint: expected 0 results, got %d", len(got))
	}
}

func TestFilterLatestVersions_FewerThanCount(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := mirror.FilterVersions(versions, strPtr("latest:5"))
	if len(got) != 2 {
		t.Errorf("expected 2 (all), got %d", len(got))
	}
}

func TestFilterLatestVersions_MoreThanCount(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0", "4.0.0")
	got := mirror.FilterVersions(versions, strPtr("latest:2"))
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].Version != "4.0.0" {
		t.Errorf("first version = %q, want 4.0.0", got[0].Version)
	}
	if got[1].Version != "3.0.0" {
		t.Errorf("second version = %q, want 3.0.0", got[1].Version)
	}
}

func TestFilterLatestVersions_ExactCount(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := mirror.FilterVersions(versions, strPtr("latest:3"))
	if len(got) != 3 {
		t.Errorf("expected 3, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// mirror.FilterVersions (integration of all formats)
// ---------------------------------------------------------------------------

func TestFilterVersions_NilFilter(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := mirror.FilterVersions(versions, nil)
	if len(got) != 2 {
		t.Errorf("nil filter should return all versions, got %d", len(got))
	}
}

func TestFilterVersions_EmptyFilter(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := mirror.FilterVersions(versions, strPtr(""))
	if len(got) != 2 {
		t.Errorf("empty filter should return all versions, got %d", len(got))
	}
}

func TestFilterVersions_LatestN(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0")
	got := mirror.FilterVersions(versions, strPtr("latest:3"))
	if len(got) != 3 {
		t.Errorf("latest:3 filter returned %d, want 3", len(got))
	}
}

func TestFilterVersions_LatestN_InvalidCount(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := mirror.FilterVersions(versions, strPtr("latest:0"))
	if len(got) != 2 {
		t.Errorf("latest:0 (invalid) should return all, got %d", len(got))
	}
}

func TestFilterVersions_LatestN_NonNumeric(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := mirror.FilterVersions(versions, strPtr("latest:abc"))
	if len(got) != 2 {
		t.Errorf("latest:abc (non-numeric) should return all, got %d", len(got))
	}
}

func TestFilterVersions_PrefixDot(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0", "2.0.0")
	got := mirror.FilterVersions(versions, strPtr("3."))
	if len(got) != 2 {
		t.Errorf("3. prefix filter returned %d, want 2", len(got))
	}
}

func TestFilterVersions_PrefixX(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0", "2.0.0")
	got := mirror.FilterVersions(versions, strPtr("3.x"))
	if len(got) != 2 {
		t.Errorf("3.x prefix filter returned %d, want 2", len(got))
	}
}

func TestFilterVersions_SemverGTE(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := mirror.FilterVersions(versions, strPtr(">=2.0.0"))
	if len(got) != 2 {
		t.Errorf(">=2.0.0 filter returned %d, want 2", len(got))
	}
}

func TestFilterVersions_CommaSeparated(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := mirror.FilterVersions(versions, strPtr("1.0.0,3.0.0"))
	if len(got) != 2 {
		t.Errorf("comma-separated filter returned %d, want 2", len(got))
	}
}

func TestFilterVersions_SingleVersion(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := mirror.FilterVersions(versions, strPtr("2.0.0"))
	if len(got) != 1 {
		t.Errorf("single version filter returned %d, want 1", len(got))
	}
	if got[0].Version != "2.0.0" {
		t.Errorf("version = %q, want 2.0.0", got[0].Version)
	}
}

// ---------------------------------------------------------------------------
// filterPlatforms
// ---------------------------------------------------------------------------

func makePlatforms(pairs ...string) []mirror.ProviderPlatform {
	out := make([]mirror.ProviderPlatform, 0, len(pairs))
	for _, p := range pairs {
		parts := splitPlatform(p)
		out = append(out, mirror.ProviderPlatform{OS: parts[0], Arch: parts[1]})
	}
	return out
}

func splitPlatform(s string) [2]string {
	for i, c := range s {
		if c == '/' {
			return [2]string{s[:i], s[i+1:]}
		}
	}
	return [2]string{s, ""}
}

func TestFilterPlatforms_NilFilter(t *testing.T) {
	platforms := makePlatforms("linux/amd64", "darwin/arm64", "windows/amd64")
	got := filterPlatforms(platforms, nil)
	if len(got) != 3 {
		t.Errorf("nil filter should return all, got %d", len(got))
	}
}

func TestFilterPlatforms_EmptyFilter(t *testing.T) {
	platforms := makePlatforms("linux/amd64", "darwin/arm64")
	got := filterPlatforms(platforms, strPtr(""))
	if len(got) != 2 {
		t.Errorf("empty filter should return all, got %d", len(got))
	}
}

func TestFilterPlatforms_ValidJSON(t *testing.T) {
	platforms := makePlatforms("linux/amd64", "darwin/arm64", "windows/amd64")
	got := filterPlatforms(platforms, strPtr(`["linux/amd64","windows/amd64"]`))
	if len(got) != 2 {
		t.Errorf("JSON filter returned %d, want 2: %v", len(got), got)
	}
	for _, p := range got {
		if p.OS == "darwin" {
			t.Error("darwin should have been filtered out")
		}
	}
}

func TestFilterPlatforms_EmptyJSONArray(t *testing.T) {
	platforms := makePlatforms("linux/amd64")
	// Empty array → return all
	got := filterPlatforms(platforms, strPtr("[]"))
	if len(got) != 1 {
		t.Errorf("empty JSON array should return all, got %d", len(got))
	}
}

func TestFilterPlatforms_InvalidJSON(t *testing.T) {
	platforms := makePlatforms("linux/amd64", "darwin/arm64")
	// Invalid JSON → fallback to all
	got := filterPlatforms(platforms, strPtr("not-json"))
	if len(got) != 2 {
		t.Errorf("invalid JSON should return all, got %d", len(got))
	}
}

func TestFilterPlatforms_CaseInsensitive(t *testing.T) {
	platforms := makePlatforms("Linux/AMD64")
	got := filterPlatforms(platforms, strPtr(`["linux/amd64"]`))
	if len(got) != 1 {
		t.Errorf("case-insensitive match should work, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// NewMirrorSyncJob
// ---------------------------------------------------------------------------

func TestNewMirrorSyncJob(t *testing.T) {
	job := NewMirrorSyncJob(nil, nil, nil, nil, nil, "")
	if job == nil {
		t.Fatal("NewMirrorSyncJob returned nil")
	}
	if job.activeSyncs == nil {
		t.Error("activeSyncs map is nil")
	}
	if job.stopCh == nil {
		t.Error("stopCh channel is nil")
	}
}

// ---------------------------------------------------------------------------
// MirrorSyncJob Start + Stop
// ---------------------------------------------------------------------------

var mirrorConfigCols = []string{
	"id", "name", "description", "upstream_registry_url", "organization_id",
	"namespace_filter", "provider_filter", "version_filter", "platform_filter",
	"enabled", "sync_interval_hours", "last_sync_at", "last_sync_status",
	"last_sync_error", "created_at", "updated_at", "created_by",
}

func newTestMirrorRepo(t *testing.T) (*repositories.MirrorRepository, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return repositories.NewMirrorRepository(sqlx.NewDb(db, "sqlmock")), mock
}

func TestMirrorSyncJob_StartStop_ContextCancel(t *testing.T) {
	mirrorRepo, mock := newTestMirrorRepo(t)
	// runScheduledSyncs queries GetMirrorsNeedingSync; return empty list
	mock.ExpectQuery("SELECT.*FROM mirror_configurations").
		WillReturnRows(sqlmock.NewRows(mirrorConfigCols))

	job := NewMirrorSyncJob(mirrorRepo, nil, nil, nil, nil, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		job.Start(ctx) // default 10-minute interval, won't fire during test
		close(done)
	}()

	// Cancel after the initial runScheduledSyncs has had time to return
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK — Start returned after ctx cancellation
	case <-time.After(3 * time.Second):
		t.Error("Start did not return after context cancellation")
	}
}

func TestMirrorSyncJob_Stop_DirectStop(t *testing.T) {
	mirrorRepo, mock := newTestMirrorRepo(t)
	mock.ExpectQuery("SELECT.*FROM mirror_configurations").
		WillReturnRows(sqlmock.NewRows(mirrorConfigCols))

	job := NewMirrorSyncJob(mirrorRepo, nil, nil, nil, nil, "")

	ctx := context.Background()
	done := make(chan struct{})

	go func() {
		job.Start(ctx)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	job.Stop()

	select {
	case <-done:
		// OK — Start returned after Stop()
	case <-time.After(3 * time.Second):
		t.Error("Start did not return after Stop()")
	}
}

// ---------------------------------------------------------------------------
// syncPlatformBinary — upstream-controlled filename validation (issue #677)
// ---------------------------------------------------------------------------

// fakeUpstreamClient is a minimal mirror.UpstreamRegistryClient stub whose
// GetProviderPackage/DownloadFileStream responses are set per test, per the
// dependency-injection contract documented on the interface itself.
type fakeUpstreamClient struct {
	pkg    *mirror.ProviderPackageResponse
	pkgErr error
	binary string // DownloadFileStream body content
	dlErr  error
}

func (f *fakeUpstreamClient) DiscoverServices(_ context.Context) (*mirror.ServiceDiscoveryResponse, error) {
	return nil, nil
}
func (f *fakeUpstreamClient) ListProviderVersions(_ context.Context, _, _ string) ([]mirror.ProviderVersion, error) {
	return nil, nil
}
func (f *fakeUpstreamClient) GetProviderPackage(_ context.Context, _, _, _, _, _ string) (*mirror.ProviderPackageResponse, error) {
	return f.pkg, f.pkgErr
}
func (f *fakeUpstreamClient) DownloadFile(_ context.Context, _ string) ([]byte, error) {
	return []byte(f.binary), f.dlErr
}
func (f *fakeUpstreamClient) DownloadFileStream(_ context.Context, _ string) (*mirror.DownloadStream, error) {
	if f.dlErr != nil {
		return nil, f.dlErr
	}
	return &mirror.DownloadStream{Body: io.NopCloser(strings.NewReader(f.binary)), ContentLength: int64(len(f.binary))}, nil
}
func (f *fakeUpstreamClient) GetProviderDocIndexByVersion(_ context.Context, _, _, _ string) ([]mirror.ProviderDocEntry, error) {
	return nil, nil
}
func (f *fakeUpstreamClient) GetProviderDocContent(_ context.Context, _ string) (string, error) {
	return "", nil
}

var _ mirror.UpstreamRegistryClient = (*fakeUpstreamClient)(nil)

// TestSyncPlatformBinary_RejectsUnsafeUpstreamFilename is the negative test for
// issue #677: an upstream package descriptor reporting a path-traversal
// filename must be rejected before it reaches the storage key. The job's
// storageBackend/providerRepo are left nil — the validation error must be
// returned before either is touched, so a regression here would panic (nil
// storageBackend.Upload) rather than silently succeed.
func TestSyncPlatformBinary_RejectsUnsafeUpstreamFilename(t *testing.T) {
	job := NewMirrorSyncJob(nil, nil, nil, nil, nil, "")
	upstream := &fakeUpstreamClient{
		pkg: &mirror.ProviderPackageResponse{
			Filename:    "../../etc/passwd",
			DownloadURL: "https://upstream.example.com/download",
		},
		binary: "fake-binary-content",
	}
	versionRecord := &models.ProviderVersion{ID: "v1"}

	err := job.syncPlatformBinary(context.Background(), upstream, versionRecord,
		"hashicorp", "aws", "5.0.0", mirror.ProviderPlatform{OS: "linux", Arch: "amd64"}, nil)
	if err == nil {
		t.Fatal("expected error for path-traversal filename from upstream package descriptor")
	}
	if !strings.Contains(err.Error(), "unsafe filename") {
		t.Errorf("error = %q, want it to mention the unsafe filename check", err.Error())
	}
}

// fakeUploadStorage is a minimal storage.Storage stub recording the path
// passed to Upload, for the positive-path test below.
type fakeUploadStorage struct {
	uploadedPath string
}

func (s *fakeUploadStorage) Upload(_ context.Context, path string, _ io.Reader, size int64) (*storage.UploadResult, error) {
	s.uploadedPath = path
	return &storage.UploadResult{Path: path, Size: size}, nil
}
func (s *fakeUploadStorage) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}
func (s *fakeUploadStorage) Delete(_ context.Context, _ string) error { return nil }
func (s *fakeUploadStorage) GetURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return "", nil
}
func (s *fakeUploadStorage) Exists(_ context.Context, _ string) (bool, error) { return false, nil }
func (s *fakeUploadStorage) GetMetadata(_ context.Context, _ string) (*storage.FileMetadata, error) {
	return nil, nil
}

var _ storage.Storage = (*fakeUploadStorage)(nil)

// TestSyncPlatformBinary_AcceptsWellFormedFilename is the positive-path
// companion: a normal upstream filename must still pass the new validation
// check and reach the storage backend, at the same storage path as before
// this fix.
func TestSyncPlatformBinary_AcceptsWellFormedFilename(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	mock.ExpectQuery("INSERT INTO provider_platforms").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("platform-1"))

	job := NewMirrorSyncJob(nil, repositories.NewProviderRepository(db), nil, nil, &fakeUploadStorage{}, "local")
	upstream := &fakeUpstreamClient{
		pkg: &mirror.ProviderPackageResponse{
			Filename:    "terraform-provider-aws_5.0.0_linux_amd64.zip",
			DownloadURL: "https://upstream.example.com/download",
		},
		binary: "fake-binary-content",
	}
	versionRecord := &models.ProviderVersion{ID: "v1"}

	err = job.syncPlatformBinary(context.Background(), upstream, versionRecord,
		"hashicorp", "aws", "5.0.0", mirror.ProviderPlatform{OS: "linux", Arch: "amd64"}, nil)
	if err != nil {
		t.Fatalf("syncPlatformBinary: %v", err)
	}
	gotStorage := job.storageBackend.(*fakeUploadStorage)
	wantPath := "providers/hashicorp/aws/5.0.0/linux/amd64/terraform-provider-aws_5.0.0_linux_amd64.zip"
	if gotStorage.uploadedPath != wantPath {
		t.Errorf("uploaded path = %q, want %q", gotStorage.uploadedPath, wantPath)
	}
}
