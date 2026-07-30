// terraform_mirror_sync_test.go tests the TerraformMirrorSyncJob lifecycle
// methods that do not require a database or real sync operations.
package jobs

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/terraform-registry/terraform-registry/internal/storage"
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

// ---------------------------------------------------------------------------
// storeVersionVerificationFiles / syncOnePlatform — orphaned blob cleanup on
// partial failure (issue #685)
// ---------------------------------------------------------------------------

// fakeMirrorStorage is a minimal storage.Storage double that records deleted
// paths, for asserting the cleanup path without a real storage backend.
type fakeMirrorStorage struct {
	deletedPaths []string
}

func (f *fakeMirrorStorage) Upload(_ context.Context, path string, _ io.Reader, _ int64) (*storage.UploadResult, error) {
	return &storage.UploadResult{Path: path, Size: 1}, nil
}
func (f *fakeMirrorStorage) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (f *fakeMirrorStorage) Delete(_ context.Context, path string) error {
	f.deletedPaths = append(f.deletedPaths, path)
	return nil
}
func (f *fakeMirrorStorage) GetURL(_ context.Context, _ string, _ time.Duration) (string, error) {
	return "", nil
}
func (f *fakeMirrorStorage) Exists(_ context.Context, _ string) (bool, error) { return true, nil }
func (f *fakeMirrorStorage) GetMetadata(_ context.Context, _ string) (*storage.FileMetadata, error) {
	return &storage.FileMetadata{}, nil
}

// TestStoreVersionVerificationFiles_UpdateFailure_CleansUpOrphanedBlobs covers
// UpdateVersionSignatureStorage failing after the SHA256SUMS and SHA256SUMS.sig
// blobs were already uploaded successfully: both orphaned blobs must be
// deleted rather than left behind with no corresponding DB row (same defect
// class as the provider-upload signature-file path fixed in issue #685).
func TestStoreVersionVerificationFiles_UpdateFailure_CleansUpOrphanedBlobs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	fakeStorage := &fakeMirrorStorage{}
	job := NewTerraformMirrorSyncJob(repo, fakeStorage, "local")

	mock.ExpectExec("UPDATE terraform_versions").WillReturnError(errors.New("db error"))

	cfg := &models.TerraformMirrorConfig{Name: "test-mirror", Tool: "terraform"}
	job.storeVersionVerificationFiles(context.Background(), cfg, "1.9.0", uuid.New(), []byte("sums-data"), []byte("sig-data"), nil, nil)

	wantSums := "terraform-binaries/1.9.0/SHA256SUMS"
	wantSig := "terraform-binaries/1.9.0/SHA256SUMS.terraform.sig"
	for _, want := range []string{wantSums, wantSig} {
		found := false
		for _, p := range fakeStorage.deletedPaths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected orphaned blob %q to be deleted after signature-storage DB update failure; deleted=%v", want, fakeStorage.deletedPaths)
		}
	}
}

// TestStoreVersionVerificationFiles_UpdateFailure_PreservesPreExistingSumsBlob
// covers the same UpdateVersionSignatureStorage failure, but for a version
// that already had a SHA256SUMS blob persisted from an earlier sync run
// (existingSumsKey non-nil). Storage paths are deterministic, so this call's
// SHA256SUMS upload overwrites that same blob in place — deleting it on
// failure would destroy content a pre-existing, untouched DB row still
// references. Only the newly-uploaded (unreferenced) signature blob should be
// cleaned up. This is the terraform-mirror-sync sibling of
// TestUploadHandler_SignatureStorageUpdateFailure_PreservesPreExistingSumsBlob
// (issue #685).
func TestStoreVersionVerificationFiles_UpdateFailure_PreservesPreExistingSumsBlob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	fakeStorage := &fakeMirrorStorage{}
	job := NewTerraformMirrorSyncJob(repo, fakeStorage, "local")

	mock.ExpectExec("UPDATE terraform_versions").WillReturnError(errors.New("db error"))

	cfg := &models.TerraformMirrorConfig{Name: "test-mirror", Tool: "terraform"}
	existingSumsKey := "terraform-binaries/1.9.0/SHA256SUMS"
	job.storeVersionVerificationFiles(context.Background(), cfg, "1.9.0", uuid.New(), []byte("sums-data"), []byte("sig-data"), &existingSumsKey, nil)

	for _, p := range fakeStorage.deletedPaths {
		if p == existingSumsKey {
			t.Errorf("pre-existing SUMS blob %q must not be deleted (an untouched DB row still references it); deleted=%v", existingSumsKey, fakeStorage.deletedPaths)
		}
	}

	wantSig := "terraform-binaries/1.9.0/SHA256SUMS.terraform.sig"
	found := false
	for _, p := range fakeStorage.deletedPaths {
		if p == wantSig {
			found = true
		}
	}
	if !found {
		t.Errorf("expected newly-uploaded (unreferenced) sig blob %q to be deleted; deleted=%v", wantSig, fakeStorage.deletedPaths)
	}
}

// TestSyncOnePlatform_UpdateSyncStatusFailure_CleansUpOrphanedBlob covers
// UpdatePlatformSyncStatus failing after the platform's binary blob was
// already uploaded successfully: the orphaned blob must be deleted and the
// failure logged rather than silently discarded, mirroring the cleanup added
// to storeVersionVerificationFiles above for the same defect class (#685).
func TestSyncOnePlatform_UpdateSyncStatusFailure_CleansUpOrphanedBlob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := repositories.NewTerraformMirrorRepository(sqlxDB)
	fakeStorage := &fakeMirrorStorage{}
	job := NewTerraformMirrorSyncJob(repo, fakeStorage, "local")

	mock.ExpectExec("UPDATE terraform_version_platforms").WillReturnError(errors.New("db error"))

	platform := models.TerraformVersionPlatform{
		ID:          uuid.New(),
		OS:          "linux",
		Arch:        "amd64",
		UpstreamURL: "https://releases.example.com/terraform_1.9.0_linux_amd64.zip",
		Filename:    "terraform_1.9.0_linux_amd64.zip",
	}

	ok := job.syncOnePlatform(context.Background(), &fakeReleasesClient{binary: "fake-binary-contents"}, "1.9.0", platform, nil, false, nil)
	if ok {
		t.Error("expected syncOnePlatform to report failure when UpdatePlatformSyncStatus fails")
	}

	wantPath := "terraform-binaries/1.9.0/linux/amd64/terraform_1.9.0_linux_amd64.zip"
	found := false
	for _, p := range fakeStorage.deletedPaths {
		if p == wantPath {
			found = true
		}
	}
	if !found {
		t.Errorf("expected orphaned blob %q to be deleted after sync-status DB update failure; deleted=%v", wantPath, fakeStorage.deletedPaths)
	}
}
