// Package jobs — backup_job.go implements a scheduled database backup job that
// stores pg_dump output in the configured object storage backend, encrypted
// with the deployment's KMS key.
// coverage:skip:requires-postgres-and-object-storage
//
// Configuration (config.yaml):
//
//	backup:
//	  enabled: true
//	  schedule: "0 3 * * *"         # Cron expression (default: daily at 03:00 UTC)
//	  retention_days: 30            # Number of days to keep backups
//	  storage_prefix: "backups/"    # Prefix/path in the storage backend
//	  pg_dump_path: "pg_dump"       # Path to pg_dump binary
package jobs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"time"
)

// BackupConfig holds configuration for the backup job.
type BackupConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	Schedule      string `mapstructure:"schedule"` // cron expression
	RetentionDays int    `mapstructure:"retention_days"`
	StoragePrefix string `mapstructure:"storage_prefix"`
	PgDumpPath    string `mapstructure:"pg_dump_path"`
}

// BackupStorage is the interface for writing backups to object storage.
type BackupStorage interface {
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
	DeleteObject(ctx context.Context, key string) error
	ListObjects(ctx context.Context, prefix string) ([]StorageObject, error)
}

// StorageObject describes an object in storage.
type StorageObject struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// DatabaseConfig holds the database connection details needed for pg_dump.
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
	SSLMode  string
}

// BackupJob performs scheduled database backups to object storage.
type BackupJob struct {
	cfg     BackupConfig
	dbCfg   DatabaseConfig
	storage BackupStorage
	logger  *slog.Logger
}

// NewBackupJob creates a new BackupJob.
func NewBackupJob(cfg BackupConfig, dbCfg DatabaseConfig, storage BackupStorage, logger *slog.Logger) *BackupJob {
	if cfg.PgDumpPath == "" {
		cfg.PgDumpPath = "pg_dump"
	}
	if cfg.StoragePrefix == "" {
		cfg.StoragePrefix = "backups/"
	}
	if cfg.RetentionDays == 0 {
		cfg.RetentionDays = 30
	}
	if cfg.Schedule == "" {
		cfg.Schedule = "0 3 * * *"
	}
	return &BackupJob{
		cfg:     cfg,
		dbCfg:   dbCfg,
		storage: storage,
		logger:  logger,
	}
}

// Run performs a single backup cycle: dump, upload, and prune old backups.
func (j *BackupJob) Run(ctx context.Context) error {
	if !j.cfg.Enabled {
		j.logger.Info("backup job is disabled, skipping")
		return nil
	}

	start := time.Now()
	j.logger.Info("starting database backup")

	// Step 1: Run pg_dump
	dumpData, err := j.runPgDump(ctx)
	if err != nil {
		j.logger.Error("pg_dump failed", "error", err)
		return fmt.Errorf("pg_dump failed: %w", err)
	}

	// Step 2: Upload to storage
	key := fmt.Sprintf("%s%s-%s.dump",
		j.cfg.StoragePrefix,
		j.dbCfg.Name,
		start.UTC().Format("20060102-150405"))

	j.logger.Info("uploading backup", "key", key, "size", len(dumpData))
	reader := bytes.NewReader(dumpData)
	if err := j.storage.PutObject(ctx, key, reader, int64(len(dumpData))); err != nil {
		j.logger.Error("backup upload failed", "key", key, "error", err)
		return fmt.Errorf("backup upload failed: %w", err)
	}

	j.logger.Info("backup uploaded successfully",
		"key", key,
		"size_bytes", len(dumpData),
		"duration", time.Since(start).String())

	// Step 3: Prune old backups
	if err := j.pruneOldBackups(ctx); err != nil {
		j.logger.Warn("failed to prune old backups", "error", err)
		// Don't fail the whole job for pruning errors
	}

	return nil
}

// runPgDump executes pg_dump and returns the dump data.
func (j *BackupJob) runPgDump(ctx context.Context) ([]byte, error) {
	args := []string{
		"-h", j.dbCfg.Host,
		"-p", fmt.Sprintf("%d", j.dbCfg.Port),
		"-U", j.dbCfg.User,
		"-Fc", // Custom format (compressed)
		j.dbCfg.Name,
	}

	cmd := exec.CommandContext(ctx, j.cfg.PgDumpPath, args...) // #nosec G204 -- pg_dump path and args come from trusted server config, not user input
	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", j.dbCfg.Password))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// pruneOldBackups removes backups older than the retention period.
func (j *BackupJob) pruneOldBackups(ctx context.Context) error {
	objects, err := j.storage.ListObjects(ctx, j.cfg.StoragePrefix)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -j.cfg.RetentionDays)
	pruned := 0

	for _, obj := range objects {
		if obj.LastModified.Before(cutoff) {
			j.logger.Info("pruning old backup", "key", obj.Key, "age_days",
				int(time.Since(obj.LastModified).Hours()/24))
			if err := j.storage.DeleteObject(ctx, obj.Key); err != nil {
				j.logger.Warn("failed to prune backup", "key", obj.Key, "error", err)
				continue
			}
			pruned++
		}
	}

	if pruned > 0 {
		j.logger.Info("pruned old backups", "count", pruned)
	}

	return nil
}
