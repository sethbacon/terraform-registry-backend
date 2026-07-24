// terraform_mirror_sync_test.go tests the TerraformMirrorSyncJob lifecycle
// methods that do not require a database or real sync operations.
package jobs

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// newTestTerraformSyncJob returns a job with nil dependencies — sufficient for
// lifecycle tests (constructor, TriggerSync) that don't exercise the sync path.
func newTestTerraformSyncJob() *TerraformMirrorSyncJob {
	return NewTerraformMirrorSyncJob(nil, nil, "local")
}

// ---------------------------------------------------------------------------
// NewTerraformMirrorSyncJob
// ---------------------------------------------------------------------------

func TestNewTerraformMirrorSyncJob_NotNil(t *testing.T) {
	job := newTestTerraformSyncJob()
	if job == nil {
		t.Fatal("NewTerraformMirrorSyncJob returned nil")
	}
}

// ---------------------------------------------------------------------------
// TriggerSync
// ---------------------------------------------------------------------------

func TestTriggerSync_Success(t *testing.T) {
	job := newTestTerraformSyncJob()
	id := uuid.New()
	if err := job.TriggerSync(context.Background(), id); err != nil {
		t.Errorf("TriggerSync returned unexpected error: %v", err)
	}
}

func TestTriggerSync_QueueFull(t *testing.T) {
	job := newTestTerraformSyncJob()
	// Fill the 16-element channel
	for i := 0; i < 16; i++ {
		if err := job.TriggerSync(context.Background(), uuid.New()); err != nil {
			t.Fatalf("unexpected error filling queue: %v", err)
		}
	}
	// 17th trigger should fail with "queue is full"
	if err := job.TriggerSync(context.Background(), uuid.New()); err == nil {
		t.Error("expected error when queue is full, got nil")
	}
}

// ---------------------------------------------------------------------------
// Start / Stop — full loop with sqlmock
// ---------------------------------------------------------------------------

func TestTerraformMirrorSyncJob_StartStop(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	job := NewTerraformMirrorSyncJob(repo, nil, "local")

	// runScheduledSyncs calls GetConfigsNeedingSync — return empty
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		_ = job.Start(ctx) // Start now blocks until Stop/ctx cancel (issue #565 finding [40])
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	if err := job.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	select {
	case <-done:
		// OK — Start returned after Stop()
	case <-time.After(3 * time.Second):
		t.Error("Start did not return after Stop()")
	}
}

func TestTerraformMirrorSyncJob_StartContextCancel(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	job := NewTerraformMirrorSyncJob(repo, nil, "local")

	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = job.Start(ctx) // Start now blocks until Stop/ctx cancel (issue #565 finding [40])
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK — Start returned after context cancellation
	case <-time.After(3 * time.Second):
		t.Error("Start did not return after context cancellation")
	}
}

// ---------------------------------------------------------------------------
// syncOnePlatform — upstream-controlled filename validation (issue #677)
// ---------------------------------------------------------------------------

// fakeReleasesClient is a minimal terraformReleasesClient stub; only
// DownloadBinaryStream is exercised by syncOnePlatform.
type fakeReleasesClient struct {
	binary string
}

func (f *fakeReleasesClient) ListVersions(_ context.Context) ([]mirror.TerraformVersionInfo, error) {
	return nil, nil
}
func (f *fakeReleasesClient) FetchSHASums(_ context.Context, _ string) (map[string]string, []byte, error) {
	return nil, nil, nil
}
func (f *fakeReleasesClient) FetchSHASumsSignature(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (f *fakeReleasesClient) DownloadBinaryStream(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	return io.NopCloser(strings.NewReader(f.binary)), int64(len(f.binary)), nil
}

var _ terraformReleasesClient = (*fakeReleasesClient)(nil)

// TestSyncOnePlatform_RejectsUnsafeUpstreamFilename is the negative test for
// issue #677: an upstream releases-index entry reporting a path-traversal
// filename must be rejected before it reaches the storage key.
func TestSyncOnePlatform_RejectsUnsafeUpstreamFilename(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	mock.ExpectExec("UPDATE terraform_version_platforms").WillReturnResult(sqlmock.NewResult(0, 1))

	repo := repositories.NewTerraformMirrorRepository(sqlx.NewDb(db, "sqlmock"))
	job := NewTerraformMirrorSyncJob(repo, nil, "local")
	client := &fakeReleasesClient{binary: "fake-binary-content"}
	p := models.TerraformVersionPlatform{ID: uuid.New(), OS: "linux", Arch: "amd64", Filename: "../../etc/passwd"}

	ok := job.syncOnePlatform(context.Background(), client, "1.7.0", p, nil, false, nil)
	if ok {
		t.Fatal("expected syncOnePlatform to fail for a path-traversal filename from the upstream releases index")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestSyncOnePlatform_AcceptsWellFormedFilename is the positive-path
// companion: a normal upstream filename must still pass the new validation
// check and reach the storage backend at the expected storage path.
func TestSyncOnePlatform_AcceptsWellFormedFilename(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	mock.ExpectExec("UPDATE terraform_version_platforms").WillReturnResult(sqlmock.NewResult(0, 1))

	repo := repositories.NewTerraformMirrorRepository(sqlx.NewDb(db, "sqlmock"))
	fakeStorage := &fakeUploadStorage{}
	job := NewTerraformMirrorSyncJob(repo, fakeStorage, "local")
	client := &fakeReleasesClient{binary: "fake-binary-content"}
	p := models.TerraformVersionPlatform{ID: uuid.New(), OS: "linux", Arch: "amd64", Filename: "terraform_1.7.0_linux_amd64.zip"}

	ok := job.syncOnePlatform(context.Background(), client, "1.7.0", p, nil, false, nil)
	if !ok {
		t.Fatal("expected syncOnePlatform to succeed for a well-formed upstream filename")
	}
	wantPath := "terraform-binaries/1.7.0/linux/amd64/terraform_1.7.0_linux_amd64.zip"
	if fakeStorage.uploadedPath != wantPath {
		t.Errorf("uploaded path = %q, want %q", fakeStorage.uploadedPath, wantPath)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
