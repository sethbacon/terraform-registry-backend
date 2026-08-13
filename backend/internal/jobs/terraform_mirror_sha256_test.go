// terraform_mirror_sha256_test.go covers issue #869: the SHA256 back-fill's
// observability and the post-sync ingestion invariant.
//
// The defect these guard against was not that the registry lacked a checksum —
// it had the right one, in storage, byte-identical to upstream. It was that
// every path which failed to put that checksum in the column returned quietly,
// so a mirrored binary that no fail-closed installer could ever accept was
// indistinguishable from one that needed no work. These tests assert on the
// specific words an operator would have to see, not merely that something was
// logged.
package jobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	dto "github.com/prometheus/client_model/go"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// captureJobLog redirects the standard logger for the duration of fn.
func captureJobLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()
	fn()
	return buf.String()
}

// sumsClient is a terraformReleasesClient whose FetchSHASums is scripted.
type sumsClient struct {
	sums map[string]string
	err  error
}

func (s *sumsClient) ListVersions(_ context.Context) ([]mirror.TerraformVersionInfo, error) {
	return nil, nil
}
func (s *sumsClient) FetchSHASums(_ context.Context, _ string) (map[string]string, []byte, error) {
	return s.sums, nil, s.err
}
func (s *sumsClient) FetchSHASumsSignature(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (s *sumsClient) DownloadBinaryStream(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	return nil, 0, errors.New("not used")
}

var _ terraformReleasesClient = (*sumsClient)(nil)

var tfMirrorVersionCols = []string{
	"id", "config_id", "version", "is_latest", "is_deprecated", "release_date",
	"sync_status", "sync_error", "synced_at", "created_at", "updated_at",
	"sums_storage_key", "sig_storage_key", "approval_status",
}

var tfMirrorPlatformCols = []string{
	"id", "version_id", "os", "arch", "upstream_url", "filename", "sha256",
	"storage_key", "storage_backend", "sha256_verified", "gpg_verified", "attestation_verified",
	"sync_status", "sync_error", "synced_at", "download_count", "created_at", "updated_at",
}

func newSHA256TestJob(t *testing.T) (*TerraformMirrorSyncJob, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := repositories.NewTerraformMirrorRepository(sqlx.NewDb(db, "sqlmock"))
	return NewTerraformMirrorSyncJob(repo, nil, "local"), mock
}

func testMirrorConfig() *models.TerraformMirrorConfig {
	return &models.TerraformMirrorConfig{ID: uuid.New(), Name: "terraform-docs-mirror", Tool: "terraform-docs"}
}

// expectVersionsMissingSHA256 scripts ListVersionsMissingSHA256 to return one
// version, and ListPlatformsForVersion to return one synced platform with no
// checksum — the shape of every affected row in issue #869.
func expectVersionsMissingSHA256(mock sqlmock.Sqlmock, cfg *models.TerraformMirrorConfig, versionID uuid.UUID) {
	mock.ExpectQuery(`SELECT.*FROM terraform_versions v\s+WHERE v.config_id`).
		WithArgs(cfg.ID).
		WillReturnRows(mock.NewRows(tfMirrorVersionCols).AddRow(
			versionID, cfg.ID, "0.24.0", false, false, nil,
			"partial", nil, nil, time.Now(), time.Now(),
			"terraform-binaries/0.24.0/SHA256SUMS", nil, "approved",
		))
}

func expectSyncedPlatformWithoutSHA256(mock sqlmock.Sqlmock, versionID, platformID uuid.UUID, filename string) {
	mock.ExpectQuery(`SELECT.*FROM terraform_version_platforms\s+WHERE version_id`).
		WithArgs(versionID).
		WillReturnRows(mock.NewRows(tfMirrorPlatformCols).AddRow(
			platformID, versionID, "linux", "amd64", "https://u", filename, "",
			nil, nil, false, false, false,
			"synced", nil, nil, 0, time.Now(), time.Now(),
		))
}

// TestBackfillSHA256_ReportsPlatformAbsentFromUpstreamSUMS is the guard for the
// silent skip. The SUMS file was fetched and parsed successfully and simply has
// no line for this platform's filename — nothing will ever fix that on its own,
// and before this change the loop moved on without a word.
func TestBackfillSHA256_ReportsPlatformAbsentFromUpstreamSUMS(t *testing.T) {
	job, mock := newSHA256TestJob(t)
	cfg := testMirrorConfig()
	versionID, platformID := uuid.New(), uuid.New()
	const filename = "terraform-docs-v0.24.0-linux-amd64.tar.gz"

	expectVersionsMissingSHA256(mock, cfg, versionID)
	expectSyncedPlatformWithoutSHA256(mock, versionID, platformID, filename)

	client := &sumsClient{sums: map[string]string{"terraform-docs-v0.24.0-linux-arm64.tar.gz": "abc"}}

	out := captureJobLog(t, func() {
		if err := job.backfillSHA256(context.Background(), client, cfg); err != nil {
			t.Fatalf("backfillSHA256: %v", err)
		}
	})

	if !strings.Contains(out, "NO CHECKSUM") {
		t.Fatalf("back-fill said nothing about a platform it could not resolve.\nlog:\n%s", out)
	}
	if !strings.Contains(out, filename) {
		t.Errorf("log does not name the unresolvable filename %q.\nlog:\n%s", filename, out)
	}
	if !strings.Contains(out, "linux/amd64") {
		t.Errorf("log does not name the platform.\nlog:\n%s", out)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// A SUMS fetch that fails (rate limit, 404, transport) leaves the rows
// unverifiable until the next run. That has to be said out loud, with the
// upstream error attached.
func TestBackfillSHA256_ReportsSUMSFetchFailure(t *testing.T) {
	job, mock := newSHA256TestJob(t)
	cfg := testMirrorConfig()
	versionID := uuid.New()

	expectVersionsMissingSHA256(mock, cfg, versionID)

	client := &sumsClient{err: fmt.Errorf("upstream returned 403: rate limited")}

	out := captureJobLog(t, func() {
		if err := job.backfillSHA256(context.Background(), client, cfg); err != nil {
			t.Fatalf("backfillSHA256: %v", err)
		}
	})

	if !strings.Contains(out, "stay unverifiable") {
		t.Fatalf("a failed SUMS fetch was not reported as leaving rows unverifiable.\nlog:\n%s", out)
	}
	if !strings.Contains(out, "rate limited") {
		t.Errorf("the upstream error was not preserved in the log.\nlog:\n%s", out)
	}
	if !strings.Contains(out, "0.24.0") {
		t.Errorf("the affected version was not named.\nlog:\n%s", out)
	}
}

// An empty-but-successful SUMS map is the third give-up branch, and used to be
// a bare `continue`.
func TestBackfillSHA256_ReportsEmptySUMSMap(t *testing.T) {
	job, mock := newSHA256TestJob(t)
	cfg := testMirrorConfig()
	versionID := uuid.New()

	expectVersionsMissingSHA256(mock, cfg, versionID)

	client := &sumsClient{sums: map[string]string{}}

	out := captureJobLog(t, func() {
		if err := job.backfillSHA256(context.Background(), client, cfg); err != nil {
			t.Fatalf("backfillSHA256: %v", err)
		}
	})

	if !strings.Contains(out, "EMPTY SUMS map") {
		t.Fatalf("an empty upstream SUMS map was skipped silently.\nlog:\n%s", out)
	}
}

// The repair itself: a synced platform with no checksum whose filename IS in
// the SUMS map gets the hash written, and the run says how many it fixed.
func TestBackfillSHA256_PopulatesMissingHash(t *testing.T) {
	job, mock := newSHA256TestJob(t)
	cfg := testMirrorConfig()
	versionID, platformID := uuid.New(), uuid.New()
	const filename = "terraform-docs-v0.24.0-linux-amd64.tar.gz"
	const hash = "9005daf969de0b50134493a2c00078b49f5f5b39d021cda7c89bf4d4f3d776d3"

	expectVersionsMissingSHA256(mock, cfg, versionID)
	expectSyncedPlatformWithoutSHA256(mock, versionID, platformID, filename)
	mock.ExpectExec(`UPDATE terraform_version_platforms\s+SET sha256`).
		WithArgs(platformID, hash).
		WillReturnResult(sqlmock.NewResult(0, 1))

	client := &sumsClient{sums: map[string]string{filename: hash}}

	out := captureJobLog(t, func() {
		if err := job.backfillSHA256(context.Background(), client, cfg); err != nil {
			t.Fatalf("backfillSHA256: %v", err)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the hash was not written back: %v", err)
	}
	if !strings.Contains(out, "populated 1 hash(es)") {
		t.Errorf("log did not report the repair.\nlog:\n%s", out)
	}
	if strings.Contains(out, "NO CHECKSUM") {
		t.Errorf("a resolved platform must not be reported as unresolvable.\nlog:\n%s", out)
	}
}

// A version whose candidate query fails must surface as an error rather than a
// clean return.
func TestBackfillSHA256_CandidateQueryError(t *testing.T) {
	job, mock := newSHA256TestJob(t)
	cfg := testMirrorConfig()

	mock.ExpectQuery(`SELECT.*FROM terraform_versions v`).
		WillReturnError(errors.New("db down"))

	err := job.backfillSHA256(context.Background(), &sumsClient{}, cfg)
	if err == nil {
		t.Fatal("expected an error when the candidate query fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to list versions missing sha256") {
		t.Errorf("err = %v, want the candidate query named", err)
	}
}

// ---------------------------------------------------------------------------
// Ingestion invariant
// ---------------------------------------------------------------------------

// TestReportUnverifiablePlatforms_FiresOnSyncedRowWithEmptySHA256 is the
// invariant's own mutation target: a platform marked synced with an empty
// sha256 is a defect state, and the run must say so in terms an operator can
// act on. The count also lands on the metric, since a log line alone cannot be
// alerted on.
func TestReportUnverifiablePlatforms_FiresOnSyncedRowWithEmptySHA256(t *testing.T) {
	job, mock := newSHA256TestJob(t)
	cfg := testMirrorConfig()

	mock.ExpectQuery(`SELECT COUNT\(\*\)\s+FROM terraform_version_platforms p`).
		WithArgs(cfg.ID).
		WillReturnRows(mock.NewRows([]string{"count"}).AddRow(3))

	var count int
	out := captureJobLog(t, func() { count = job.reportUnverifiablePlatforms(context.Background(), cfg) })

	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}
	if !strings.Contains(out, "INVARIANT VIOLATION") {
		t.Fatalf("three unverifiable platforms produced no invariant report.\nlog:\n%s", out)
	}
	if !strings.Contains(out, "terraform-docs-mirror") {
		t.Errorf("the report does not name the mirror config.\nlog:\n%s", out)
	}
	if !strings.Contains(out, "verify-mirror-sha256") {
		t.Errorf("the report does not tell the operator how to get the list.\nlog:\n%s", out)
	}
	if got := testutilGaugeValue(t, cfg); got != 3 {
		t.Errorf("gauge = %v, want 3", got)
	}
}

// A clean config must report zero rather than nothing: "checked, clean" and
// "never checked" have to be distinguishable, which is precisely what was
// missing while this sat unnoticed.
func TestReportUnverifiablePlatforms_SetsZeroWhenClean(t *testing.T) {
	job, mock := newSHA256TestJob(t)
	cfg := testMirrorConfig()
	cfg.Name = "clean-mirror"

	// Seed the series with a previous run's non-zero reading. Without this the
	// gauge would read 0 simply because it had never been set, and the
	// assertion below would hold even if the clean path stopped publishing —
	// which is exactly how a stale alert survives a fixed mirror.
	telemetry.TerraformMirrorUnverifiablePlatforms.WithLabelValues(cfg.Name, cfg.Tool).Set(7)

	mock.ExpectQuery(`SELECT COUNT\(\*\)\s+FROM terraform_version_platforms p`).
		WithArgs(cfg.ID).
		WillReturnRows(mock.NewRows([]string{"count"}).AddRow(0))

	var count int
	out := captureJobLog(t, func() { count = job.reportUnverifiablePlatforms(context.Background(), cfg) })

	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
	if strings.Contains(out, "INVARIANT VIOLATION") {
		t.Errorf("a clean config must not report a violation.\nlog:\n%s", out)
	}
	if got := testutilGaugeValue(t, cfg); got != 0 {
		t.Errorf("gauge = %v, want 0 — a clean config must publish 0, not leave the series stale", got)
	}
}

// A failed invariant check must not read as clean.
func TestReportUnverifiablePlatforms_QueryErrorIsReported(t *testing.T) {
	job, mock := newSHA256TestJob(t)
	cfg := testMirrorConfig()

	mock.ExpectQuery(`SELECT COUNT\(\*\)\s+FROM terraform_version_platforms p`).
		WillReturnError(errors.New("db down"))

	out := captureJobLog(t, func() { job.reportUnverifiablePlatforms(context.Background(), cfg) })

	if !strings.Contains(out, "failed to check the sha256 ingestion invariant") {
		t.Errorf("a failed invariant check was not reported.\nlog:\n%s", out)
	}
}

func testutilGaugeValue(t *testing.T, cfg *models.TerraformMirrorConfig) float64 {
	t.Helper()
	var m dto.Metric
	g, err := telemetry.TerraformMirrorUnverifiablePlatforms.GetMetricWithLabelValues(cfg.Name, cfg.Tool)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	if err := g.Write(&m); err != nil {
		t.Fatalf("gauge Write: %v", err)
	}
	return m.GetGauge().GetValue()
}

// ---------------------------------------------------------------------------
// syncOnePlatform — sha256_verified must reflect the row, not the blob
// ---------------------------------------------------------------------------

// existsStorage reports every key as already present, which drives
// syncOnePlatform down its "already stored" short-circuit.
type existsStorage struct{ fakeMirrorStorage }

func (e *existsStorage) Exists(_ context.Context, _ string) (bool, error) { return true, nil }

// TestSyncOnePlatform_AlreadyStoredWithoutSHA256IsNotVerified: the
// short-circuit for a platform whose blob is already in storage used to assert
// sha256_verified=true unconditionally. For the rows of issue #869 — synced,
// blob present, sha256 empty — that made the admin view claim verification for
// exactly the binaries the download API was serving with no checksum.
func TestSyncOnePlatform_AlreadyStoredWithoutSHA256IsNotVerified(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	platformID := uuid.New()
	key := "terraform-binaries/0.24.0/linux/amd64/terraform-docs-v0.24.0-linux-amd64.tar.gz"

	// $5 is sha256_verified. false is the assertion.
	mock.ExpectExec(`UPDATE terraform_version_platforms`).
		WithArgs(platformID, "synced", key, "local", false, false, false, nil, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := repositories.NewTerraformMirrorRepository(sqlx.NewDb(db, "sqlmock"))
	job := NewTerraformMirrorSyncJob(repo, &existsStorage{}, "local")

	p := models.TerraformVersionPlatform{
		ID: platformID, OS: "linux", Arch: "amd64",
		Filename: "terraform-docs-v0.24.0-linux-amd64.tar.gz",
		SHA256:   "", StorageKey: &key,
	}
	if ok := job.syncOnePlatform(context.Background(), &sumsClient{}, "0.24.0", p, nil, false, nil); !ok {
		t.Fatal("expected the already-stored short-circuit to succeed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sha256_verified was not written as false for a row with no checksum: %v", err)
	}
}

// The companion: a stored blob WITH a checksum stays verified.
func TestSyncOnePlatform_AlreadyStoredWithSHA256StaysVerified(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	platformID := uuid.New()
	key := "terraform-binaries/1.9.0/linux/amd64/terraform_1.9.0_linux_amd64.zip"

	mock.ExpectExec(`UPDATE terraform_version_platforms`).
		WithArgs(platformID, "synced", key, "local", true, false, false, nil, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := repositories.NewTerraformMirrorRepository(sqlx.NewDb(db, "sqlmock"))
	job := NewTerraformMirrorSyncJob(repo, &existsStorage{}, "local")

	p := models.TerraformVersionPlatform{
		ID: platformID, OS: "linux", Arch: "amd64",
		Filename: "terraform_1.9.0_linux_amd64.zip",
		SHA256:   "deadbeef", StorageKey: &key,
	}
	if ok := job.syncOnePlatform(context.Background(), &sumsClient{}, "1.9.0", p, nil, false, nil); !ok {
		t.Fatal("expected the already-stored short-circuit to succeed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sha256_verified was not written as true for a row with a checksum: %v", err)
	}
}
