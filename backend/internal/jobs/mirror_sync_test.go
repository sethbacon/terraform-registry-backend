package jobs

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
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
// parseSemverParts
// ---------------------------------------------------------------------------

func TestParseSemverParts(t *testing.T) {
	tests := []struct {
		version string
		want    [3]int
	}{
		{"1.2.3", [3]int{1, 2, 3}},
		{"10.20.30", [3]int{10, 20, 30}},
		{"1.2.3-beta.1", [3]int{1, 2, 3}}, // pre-release stripped
		{"1.2.3+build", [3]int{1, 2, 0}},  // build meta: '+' not stripped, so "3+build" fails Atoi → 0
		{"1.2", [3]int{1, 2, 0}},          // missing patch → 0
		{"1", [3]int{1, 0, 0}},            // only major
		{"abc", [3]int{0, 0, 0}},          // non-numeric
	}
	for _, tt := range tests {
		got := parseSemverParts(tt.version)
		if got != tt.want {
			t.Errorf("parseSemverParts(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// compareSemver
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
	}
	for _, tt := range tests {
		got := compareSemver(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
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
// filterVersionsByPrefix
// ---------------------------------------------------------------------------

func TestFilterVersionsByPrefix(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0", "2.0.0", "4.0.0")

	got := filterVersionsByPrefix(versions, "3.")
	if len(got) != 2 {
		t.Errorf("expected 2 versions with prefix 3., got %d: %v", len(got), versionNames(got))
	}
}

func TestFilterVersionsByPrefix_NoMatch(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0")
	got := filterVersionsByPrefix(versions, "5.")
	if len(got) != 0 {
		t.Errorf("expected empty, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// filterVersionsByList
// ---------------------------------------------------------------------------

func TestFilterVersionsByList(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0", "2.0.0", "4.0.0")
	got := filterVersionsByList(versions, "3.74.0,2.0.0")
	if len(got) != 2 {
		t.Errorf("expected 2, got %d: %v", len(got), versionNames(got))
	}
}

func TestFilterVersionsByList_WithSpaces(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := filterVersionsByList(versions, " 1.0.0 , 2.0.0 ")
	if len(got) != 2 {
		t.Errorf("expected 2, got %d", len(got))
	}
}

func TestFilterVersionsByList_NoMatch(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := filterVersionsByList(versions, "9.9.9")
	if len(got) != 0 {
		t.Errorf("expected empty, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// filterVersionsBySemverConstraint
// ---------------------------------------------------------------------------

func TestFilterVersionsBySemverConstraint(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0", "4.0.0")

	tests := []struct {
		constraint string
		wantCount  int
	}{
		{">=3.0.0", 2}, // 3.0.0 and 4.0.0
		{">3.0.0", 1},  // only 4.0.0
		{"<=2.0.0", 2}, // 1.0.0 and 2.0.0
		{"<2.0.0", 1},  // only 1.0.0
	}

	for _, tt := range tests {
		got := filterVersionsBySemverConstraint(versions, tt.constraint)
		if len(got) != tt.wantCount {
			t.Errorf("filterVersionsBySemverConstraint(%q) = %v (len %d), want len %d",
				tt.constraint, versionNames(got), len(got), tt.wantCount)
		}
	}
}

func TestFilterVersionsBySemverConstraint_NoOp(t *testing.T) {
	// Without a recognized operator prefix, returns all
	versions := makeVersions("1.0.0", "2.0.0")
	got := filterVersionsBySemverConstraint(versions, "~>1.0")
	if len(got) != len(versions) {
		t.Errorf("expected all versions returned for unrecognized constraint")
	}
}

// ---------------------------------------------------------------------------
// filterLatestVersions
// ---------------------------------------------------------------------------

func TestFilterLatestVersions_FewerThanCount(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := filterLatestVersions(versions, 5)
	if len(got) != 2 {
		t.Errorf("expected 2 (all), got %d", len(got))
	}
}

func TestFilterLatestVersions_MoreThanCount(t *testing.T) {
	// Sorted descending, take top 2 → 4.0.0, 3.0.0
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0", "4.0.0")
	got := filterLatestVersions(versions, 2)
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
	got := filterLatestVersions(versions, 3)
	if len(got) != 3 {
		t.Errorf("expected 3, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// filterVersions (integration of all formats)
// ---------------------------------------------------------------------------

func TestFilterVersions_NilFilter(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := filterVersions(versions, nil)
	if len(got) != 2 {
		t.Errorf("nil filter should return all versions, got %d", len(got))
	}
}

func TestFilterVersions_EmptyFilter(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := filterVersions(versions, strPtr(""))
	if len(got) != 2 {
		t.Errorf("empty filter should return all versions, got %d", len(got))
	}
}

func TestFilterVersions_LatestN(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0")
	got := filterVersions(versions, strPtr("latest:3"))
	if len(got) != 3 {
		t.Errorf("latest:3 filter returned %d, want 3", len(got))
	}
}

func TestFilterVersions_LatestN_InvalidCount(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	// latest:0 → invalid count → return all
	got := filterVersions(versions, strPtr("latest:0"))
	if len(got) != 2 {
		t.Errorf("latest:0 (invalid) should return all, got %d", len(got))
	}
}

func TestFilterVersions_LatestN_NonNumeric(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0")
	got := filterVersions(versions, strPtr("latest:abc"))
	if len(got) != 2 {
		t.Errorf("latest:abc (non-numeric) should return all, got %d", len(got))
	}
}

func TestFilterVersions_PrefixDot(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0", "2.0.0")
	got := filterVersions(versions, strPtr("3."))
	if len(got) != 2 {
		t.Errorf("3. prefix filter returned %d, want 2", len(got))
	}
}

func TestFilterVersions_PrefixX(t *testing.T) {
	versions := makeVersions("3.74.0", "3.73.0", "2.0.0")
	got := filterVersions(versions, strPtr("3.x"))
	if len(got) != 2 {
		t.Errorf("3.x prefix filter returned %d, want 2", len(got))
	}
}

func TestFilterVersions_SemverGTE(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := filterVersions(versions, strPtr(">=2.0.0"))
	if len(got) != 2 {
		t.Errorf(">=2.0.0 filter returned %d, want 2", len(got))
	}
}

func TestFilterVersions_CommaSeparated(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := filterVersions(versions, strPtr("1.0.0,3.0.0"))
	if len(got) != 2 {
		t.Errorf("comma-separated filter returned %d, want 2", len(got))
	}
}

func TestFilterVersions_SingleVersion(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := filterVersions(versions, strPtr("2.0.0"))
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
	job := NewMirrorSyncJob(nil, nil, nil, "")
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

	job := NewMirrorSyncJob(mirrorRepo, nil, nil, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		job.Start(ctx, 60) // 60-minute interval, won't fire during test
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

	job := NewMirrorSyncJob(mirrorRepo, nil, nil, "")

	ctx := context.Background()
	done := make(chan struct{})

	go func() {
		job.Start(ctx, 60)
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
