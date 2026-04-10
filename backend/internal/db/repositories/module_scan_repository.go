// module_scan_repository.go implements database operations for module security scan records.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/scanner"
)

// ErrScanAlreadyClaimed is returned by MarkScanning when another worker has already
// claimed the scan record (status is no longer 'pending').
var ErrScanAlreadyClaimed = errors.New("scan already claimed by another worker")

// ModuleScanRepository handles database operations for module_version_scans.
type ModuleScanRepository struct {
	db *sql.DB
}

// NewModuleScanRepository constructs a ModuleScanRepository.
func NewModuleScanRepository(db *sql.DB) *ModuleScanRepository {
	return &ModuleScanRepository{db: db}
}

// CreatePendingScan inserts a pending scan record for the given module version.
// It is idempotent: if a scan already exists for this version it is a no-op.
func (r *ModuleScanRepository) CreatePendingScan(ctx context.Context, moduleVersionID string) error {
	const q = `
		INSERT INTO module_version_scans (module_version_id, scanner, status)
		VALUES ($1, 'pending', 'pending')
		ON CONFLICT (module_version_id) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, q, moduleVersionID)
	if err != nil {
		return fmt.Errorf("create pending scan: %w", err)
	}
	return nil
}

// ListPendingScans returns up to limit scan records with status 'pending',
// ordered by creation time ascending (FIFO).
func (r *ModuleScanRepository) ListPendingScans(ctx context.Context, limit int) ([]*models.ModuleScan, error) {
	const q = `
		SELECT id, module_version_id, scanner, scanner_version, expected_version,
		       status, scanned_at, critical_count, high_count, medium_count, low_count,
		       raw_results, error_message, created_at, updated_at
		FROM module_version_scans
		WHERE status = 'pending'
		ORDER BY created_at
		LIMIT $1
	`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending scans: %w", err)
	}
	defer rows.Close()

	var scans []*models.ModuleScan
	for rows.Next() {
		s := &models.ModuleScan{}
		var rawResults []byte
		if err := rows.Scan(
			&s.ID, &s.ModuleVersionID, &s.Scanner, &s.ScannerVersion, &s.ExpectedVersion,
			&s.Status, &s.ScannedAt, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount,
			&rawResults, &s.ErrorMessage, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		if len(rawResults) > 0 {
			s.RawResults = json.RawMessage(rawResults)
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

// MarkScanning transitions a pending scan to 'scanning'.
// Uses a conditional UPDATE to prevent two workers from claiming the same record.
// Returns ErrScanAlreadyClaimed if no rows are updated.
func (r *ModuleScanRepository) MarkScanning(ctx context.Context, scanID string) error {
	const q = `
		UPDATE module_version_scans
		SET status = 'scanning', updated_at = NOW()
		WHERE id = $1 AND status = 'pending'
	`
	res, err := r.db.ExecContext(ctx, q, scanID)
	if err != nil {
		return fmt.Errorf("mark scanning: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrScanAlreadyClaimed
	}
	return nil
}

// MarkComplete records a successful scan result.
func (r *ModuleScanRepository) MarkComplete(
	ctx context.Context,
	scanID string,
	result *scanner.ScanResult,
	expectedVersion string,
) error {
	status := "clean"
	if result.HasFindings {
		status = "findings"
	}
	now := time.Now()

	rawJSON := result.RawJSON
	if len(rawJSON) == 0 {
		rawJSON = json.RawMessage(`{}`)
	}

	var expVer *string
	if expectedVersion != "" {
		expVer = &expectedVersion
	}
	actualVer := &result.ScannerVersion

	const q = `
		UPDATE module_version_scans
		SET status = $2, scanned_at = $3, scanner_version = $4, expected_version = $5,
		    critical_count = $6, high_count = $7, medium_count = $8, low_count = $9,
		    raw_results = $10, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, q,
		scanID, status, now, actualVer, expVer,
		result.CriticalCount, result.HighCount, result.MediumCount, result.LowCount,
		rawJSON,
	)
	if err != nil {
		return fmt.Errorf("mark complete: %w", err)
	}
	return nil
}

// MarkError records a scan that failed due to a processing error.
func (r *ModuleScanRepository) MarkError(ctx context.Context, scanID, errMsg string) error {
	const q = `
		UPDATE module_version_scans
		SET status = 'error', error_message = $2, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, q, scanID, errMsg)
	if err != nil {
		return fmt.Errorf("mark error: %w", err)
	}
	return nil
}

// GetLatestScan returns the most recent scan for a module version, or nil if none exists.
func (r *ModuleScanRepository) GetLatestScan(ctx context.Context, moduleVersionID string) (*models.ModuleScan, error) {
	const q = `
		SELECT id, module_version_id, scanner, scanner_version, expected_version,
		       status, scanned_at, critical_count, high_count, medium_count, low_count,
		       raw_results, error_message, created_at, updated_at
		FROM module_version_scans
		WHERE module_version_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`
	s := &models.ModuleScan{}
	var rawResults []byte
	err := r.db.QueryRowContext(ctx, q, moduleVersionID).Scan(
		&s.ID, &s.ModuleVersionID, &s.Scanner, &s.ScannerVersion, &s.ExpectedVersion,
		&s.Status, &s.ScannedAt, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount,
		&rawResults, &s.ErrorMessage, &s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get latest scan: %w", err)
	}
	if len(rawResults) > 0 {
		s.RawResults = json.RawMessage(rawResults)
	}
	return s, nil
}

// ResetStaleScanningRecords resets records stuck in 'scanning' for longer than olderThan.
// This recovers from worker crashes.
func (r *ModuleScanRepository) ResetStaleScanningRecords(ctx context.Context, olderThan time.Duration) error {
	const q = `
		UPDATE module_version_scans
		SET status = 'pending', updated_at = NOW()
		WHERE status = 'scanning'
		  AND updated_at < NOW() - $1::interval
	`
	_, err := r.db.ExecContext(ctx, q, fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return fmt.Errorf("reset stale scanning: %w", err)
	}
	return nil
}
