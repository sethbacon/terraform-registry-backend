package jobs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

type mockBackupStorage struct {
	putErr    error
	listErr   error
	deleteErr error
	objects   []StorageObject
	putCalled int
	putKeys   []string
	delKeys   []string
}

func (m *mockBackupStorage) PutObject(_ context.Context, key string, _ io.Reader, _ int64) error {
	m.putCalled++
	m.putKeys = append(m.putKeys, key)
	return m.putErr
}

func (m *mockBackupStorage) DeleteObject(_ context.Context, key string) error {
	m.delKeys = append(m.delKeys, key)
	return m.deleteErr
}

func (m *mockBackupStorage) ListObjects(_ context.Context, _ string) ([]StorageObject, error) {
	return m.objects, m.listErr
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewBackupJob_Defaults(t *testing.T) {
	cfg := BackupConfig{Enabled: true}
	dbCfg := DatabaseConfig{Host: "localhost", Port: 5432, User: "pg", Name: "test"}
	j := NewBackupJob(cfg, dbCfg, nil, testLogger())

	if j.cfg.PgDumpPath != "pg_dump" {
		t.Errorf("PgDumpPath = %q, want pg_dump", j.cfg.PgDumpPath)
	}
	if j.cfg.StoragePrefix != "backups/" {
		t.Errorf("StoragePrefix = %q, want backups/", j.cfg.StoragePrefix)
	}
	if j.cfg.RetentionDays != 30 {
		t.Errorf("RetentionDays = %d, want 30", j.cfg.RetentionDays)
	}
	if j.cfg.Schedule != "0 3 * * *" {
		t.Errorf("Schedule = %q, want '0 3 * * *'", j.cfg.Schedule)
	}
}

func TestNewBackupJob_CustomValues(t *testing.T) {
	cfg := BackupConfig{
		Enabled:       true,
		PgDumpPath:    "/usr/bin/pg_dump",
		StoragePrefix: "custom/",
		RetentionDays: 7,
		Schedule:      "0 0 * * *",
	}
	j := NewBackupJob(cfg, DatabaseConfig{}, nil, testLogger())

	if j.cfg.PgDumpPath != "/usr/bin/pg_dump" {
		t.Errorf("PgDumpPath = %q, want /usr/bin/pg_dump", j.cfg.PgDumpPath)
	}
	if j.cfg.StoragePrefix != "custom/" {
		t.Errorf("StoragePrefix = %q, want custom/", j.cfg.StoragePrefix)
	}
	if j.cfg.RetentionDays != 7 {
		t.Errorf("RetentionDays = %d, want 7", j.cfg.RetentionDays)
	}
}

func TestBackupJob_RunDisabled(t *testing.T) {
	j := NewBackupJob(BackupConfig{Enabled: false}, DatabaseConfig{}, nil, testLogger())

	err := j.Run(context.Background())
	if err != nil {
		t.Errorf("Run() with disabled config = %v, want nil", err)
	}
}

func TestBackupJob_PruneOldBackups(t *testing.T) {
	old := time.Now().AddDate(0, 0, -60)
	recent := time.Now().AddDate(0, 0, -5)

	storage := &mockBackupStorage{
		objects: []StorageObject{
			{Key: "backups/old.dump", LastModified: old},
			{Key: "backups/recent.dump", LastModified: recent},
		},
	}

	j := NewBackupJob(
		BackupConfig{Enabled: true, RetentionDays: 30, StoragePrefix: "backups/"},
		DatabaseConfig{},
		storage,
		testLogger(),
	)

	err := j.pruneOldBackups(context.Background())
	if err != nil {
		t.Fatalf("pruneOldBackups() = %v", err)
	}

	if len(storage.delKeys) != 1 {
		t.Fatalf("deleted %d objects, want 1", len(storage.delKeys))
	}
	if storage.delKeys[0] != "backups/old.dump" {
		t.Errorf("deleted %q, want backups/old.dump", storage.delKeys[0])
	}
}

func TestBackupJob_PruneNoExpired(t *testing.T) {
	recent := time.Now().AddDate(0, 0, -1)
	storage := &mockBackupStorage{
		objects: []StorageObject{
			{Key: "backups/fresh.dump", LastModified: recent},
		},
	}

	j := NewBackupJob(
		BackupConfig{Enabled: true, RetentionDays: 30, StoragePrefix: "backups/"},
		DatabaseConfig{},
		storage,
		testLogger(),
	)

	err := j.pruneOldBackups(context.Background())
	if err != nil {
		t.Fatalf("pruneOldBackups() = %v", err)
	}
	if len(storage.delKeys) != 0 {
		t.Errorf("deleted %d objects, want 0", len(storage.delKeys))
	}
}

func TestBackupJob_PruneListError(t *testing.T) {
	storage := &mockBackupStorage{
		listErr: fmt.Errorf("network error"),
	}

	j := NewBackupJob(
		BackupConfig{Enabled: true, RetentionDays: 30, StoragePrefix: "backups/"},
		DatabaseConfig{},
		storage,
		testLogger(),
	)

	err := j.pruneOldBackups(context.Background())
	if err == nil {
		t.Fatal("pruneOldBackups() = nil, want error")
	}
}

func TestBackupJob_PruneDeleteError(t *testing.T) {
	old := time.Now().AddDate(0, 0, -60)
	storage := &mockBackupStorage{
		objects:   []StorageObject{{Key: "backups/old.dump", LastModified: old}},
		deleteErr: fmt.Errorf("delete failed"),
	}

	j := NewBackupJob(
		BackupConfig{Enabled: true, RetentionDays: 30, StoragePrefix: "backups/"},
		DatabaseConfig{},
		storage,
		testLogger(),
	)

	// Should not fail — prune errors are non-fatal
	err := j.pruneOldBackups(context.Background())
	if err != nil {
		t.Fatalf("pruneOldBackups() = %v, want nil (non-fatal)", err)
	}
}
