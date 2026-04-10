// module_scanner_job.go implements a background job that processes pending module
// security scans using the configured scanner tool.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/archiver"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/safego"
	"github.com/terraform-registry/terraform-registry/internal/scanner"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// ModuleScannerJob polls for pending scan records and dispatches them to the
// configured scanner tool. Designed after the APIKeyExpiryNotifier pattern.
type ModuleScannerJob struct {
	cfg        *config.ScanningConfig
	scanRepo   *repositories.ModuleScanRepository
	moduleRepo *repositories.ModuleRepository
	storage    storage.Storage
	stopChan   chan struct{}
}

// NewModuleScannerJob constructs a ModuleScannerJob.
func NewModuleScannerJob(
	cfg *config.ScanningConfig,
	scanRepo *repositories.ModuleScanRepository,
	moduleRepo *repositories.ModuleRepository,
	storageBackend storage.Storage,
) *ModuleScannerJob {
	return &ModuleScannerJob{
		cfg:        cfg,
		scanRepo:   scanRepo,
		moduleRepo: moduleRepo,
		storage:    storageBackend,
		stopChan:   make(chan struct{}),
	}
}

// Name returns the human-readable job name used in logs.
func (j *ModuleScannerJob) Name() string { return "module-scanner" }

// Start begins the scan polling loop.  It is a no-op when scanning is disabled
// or the binary path is not configured.
func (j *ModuleScannerJob) Start(ctx context.Context) error {
	if !j.cfg.Enabled {
		slog.Info("module scanner: disabled (scanning.enabled=false)")
		return nil
	}
	if j.cfg.BinaryPath == "" {
		slog.Info("module scanner: disabled (scanning.binary_path not set)")
		return nil
	}

	s, err := scanner.New(j.cfg)
	if err != nil {
		slog.Error("module scanner: failed to construct scanner", "error", err)
		return nil // non-fatal — do not crash the server
	}

	// Supply-chain version pinning check.
	actualVersion, err := s.Version(ctx)
	if err != nil {
		slog.Error("module scanner: cannot get binary version",
			"tool", j.cfg.Tool, "binary", j.cfg.BinaryPath, "error", err)
		return nil
	}
	if j.cfg.ExpectedVersion != "" && actualVersion != j.cfg.ExpectedVersion {
		slog.Error("module scanner: binary version mismatch — refusing to run",
			"tool", j.cfg.Tool,
			"expected", j.cfg.ExpectedVersion,
			"actual", actualVersion,
			"binary", j.cfg.BinaryPath,
			"action", "update scanning.expected_version in config or reinstall the expected binary")
		return nil
	}
	slog.Info("module scanner: started", "tool", s.Name(), "version", actualVersion)

	// Recover stale 'scanning' records left by a previous crash.
	_ = j.scanRepo.ResetStaleScanningRecords(ctx, 30*time.Minute)

	interval := time.Duration(j.cfg.ScanIntervalMins) * time.Minute
	if interval == 0 {
		interval = 5 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately before entering the ticker loop.
	j.runScanCycle(ctx, s, actualVersion)

	for {
		select {
		case <-ticker.C:
			j.runScanCycle(ctx, s, actualVersion)
		case <-j.stopChan:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// Stop signals the job to exit gracefully.
func (j *ModuleScannerJob) Stop() error {
	select {
	case <-j.stopChan:
		// already stopped
	default:
		close(j.stopChan)
	}
	return nil
}

// coverage:skip:integration-only — requires real scanner binary, DB, and storage
func (j *ModuleScannerJob) runScanCycle(ctx context.Context, s scanner.Scanner, version string) {
	workerCount := j.cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = 2
	}

	pending, err := j.scanRepo.ListPendingScans(ctx, workerCount*2)
	if err != nil {
		slog.Error("module scanner: failed to list pending scans", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	sem := make(chan struct{}, workerCount)
	var wg sync.WaitGroup
	for _, scan := range pending {
		scan := scan
		sem <- struct{}{}
		wg.Add(1)
		safego.Go(func() {
			defer func() { <-sem; wg.Done() }()
			j.scanOne(ctx, s, scan.ID, scan.ModuleVersionID, version)
		})
	}
	wg.Wait()
}

// coverage:skip:integration-only — requires real scanner binary, DB, and storage
func (j *ModuleScannerJob) scanOne(ctx context.Context, s scanner.Scanner, scanID, moduleVersionID, actualVersion string) {
	if err := j.scanRepo.MarkScanning(ctx, scanID); err != nil {
		if errors.Is(err, repositories.ErrScanAlreadyClaimed) {
			return // another worker got it first
		}
		slog.Error("module scanner: failed to mark scanning", "scan_id", scanID, "error", err)
		return
	}

	mv, err := j.moduleRepo.GetVersionByID(ctx, moduleVersionID)
	if err != nil || mv == nil {
		_ = j.scanRepo.MarkError(ctx, scanID, "module version not found")
		return
	}

	tmpDir, err := os.MkdirTemp("", "scan-*")
	if err != nil {
		_ = j.scanRepo.MarkError(ctx, scanID, fmt.Sprintf("mkdirtemp: %v", err))
		return
	}
	defer os.RemoveAll(tmpDir)

	reader, err := j.storage.Download(ctx, mv.StoragePath)
	if err != nil {
		_ = j.scanRepo.MarkError(ctx, scanID, fmt.Sprintf("download: %v", err))
		return
	}
	defer reader.Close()

	if err := archiver.ExtractTarGz(reader, tmpDir); err != nil {
		_ = j.scanRepo.MarkError(ctx, scanID, fmt.Sprintf("extract: %v", err))
		return
	}

	result, err := s.ScanDirectory(ctx, tmpDir)
	if err != nil {
		_ = j.scanRepo.MarkError(ctx, scanID, err.Error())
		return
	}
	result.ScannerVersion = actualVersion

	if err := j.scanRepo.MarkComplete(ctx, scanID, result, j.cfg.ExpectedVersion); err != nil {
		slog.Error("module scanner: failed to store result", "scan_id", scanID, "error", err)
		return
	}

	slog.Info("module scanner: scan complete",
		"version_id", moduleVersionID,
		"tool", s.Name(),
		"critical", result.CriticalCount,
		"high", result.HighCount)
}
