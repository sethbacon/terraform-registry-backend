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

// UpsertPendingScan inserts a new pending scan record, or resets an existing
// completed/errored record back to pending so the worker will re-process it.
// Records that are already pending or actively scanning are left untouched to
// avoid interrupting an in-flight scan.
func (r *ModuleScanRepository) UpsertPendingScan(ctx context.Context, moduleVersionID string) error {
	const q = `
		INSERT INTO module_version_scans (module_version_id, scanner, status)
		VALUES ($1, 'pending', 'pending')
		ON CONFLICT (module_version_id) DO UPDATE
			SET status        = 'pending',
			    error_message = NULL,
			    updated_at    = NOW()
			WHERE module_version_scans.status NOT IN ('pending', 'scanning')
	`
	_, err := r.db.ExecContext(ctx, q, moduleVersionID)
	if err != nil {
		return fmt.Errorf("upsert pending scan: %w", err)
	}
	return nil
}

// ListPendingScans returns up to limit scan records with status 'pending',
// ordered by creation time ascending (FIFO).
func (r *ModuleScanRepository) ListPendingScans(ctx context.Context, limit int) ([]*models.ModuleScan, error) {
	const q = `
		SELECT id, module_version_id, scanner, scanner_version, expected_version,
		       status, scanned_at, critical_count, high_count, medium_count, low_count,
		       raw_results, error_message, execution_log, created_at, updated_at
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
			&rawResults, &s.ErrorMessage, &s.ExecutionLog, &s.CreatedAt, &s.UpdatedAt,
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

// ClaimPendingScans atomically claims up to limit pending scan records for the
// calling worker, transitioning them from 'pending' to 'scanning' in a single
// statement and returning the claimed rows. It uses FOR UPDATE SKIP LOCKED so
// concurrent workers claim disjoint batches without blocking or racing on the
// same rows, which lets scan workers scale horizontally without wasted
// contention. The returned records are already marked 'scanning'; callers must
// NOT call MarkScanning for them.
func (r *ModuleScanRepository) ClaimPendingScans(ctx context.Context, limit int) ([]*models.ModuleScan, error) {
	const q = `
		UPDATE module_version_scans
		SET status = 'scanning', updated_at = NOW()
		WHERE id IN (
			SELECT id FROM module_version_scans
			WHERE status = 'pending'
			ORDER BY created_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, module_version_id, scanner, scanner_version, expected_version,
		          status, scanned_at, critical_count, high_count, medium_count, low_count,
		          raw_results, error_message, execution_log, created_at, updated_at
	`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("claim pending scans: %w", err)
	}
	defer rows.Close()

	var scans []*models.ModuleScan
	for rows.Next() {
		s := &models.ModuleScan{}
		var rawResults []byte
		if err := rows.Scan(
			&s.ID, &s.ModuleVersionID, &s.Scanner, &s.ScannerVersion, &s.ExpectedVersion,
			&s.Status, &s.ScannedAt, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount,
			&rawResults, &s.ErrorMessage, &s.ExecutionLog, &s.CreatedAt, &s.UpdatedAt,
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
	scannerName string,
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
	var execLog *string
	if result.ExecutionLog != "" {
		execLog = &result.ExecutionLog
	}

	const q = `
		UPDATE module_version_scans
		SET scanner = $2, status = $3, scanned_at = $4, scanner_version = $5, expected_version = $6,
		    critical_count = $7, high_count = $8, medium_count = $9, low_count = $10,
		    raw_results = $11, execution_log = $12, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, q,
		scanID, scannerName, status, now, actualVer, expVer,
		result.CriticalCount, result.HighCount, result.MediumCount, result.LowCount,
		rawJSON, execLog,
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
// GetLatestScan fetches the newest scan for a module version, bound to a tenancy.
//
// Scoped for the same reason as GetScanByID: module_version_scans is
// organization-owned only transitively, so an accessor without a tenant
// parameter is one every caller has to remember to guard. The signature-replay
// gate flagged this the moment its sibling was scoped -- which is the point of
// scoping the accessor rather than the handler.
//
// Its one caller resolves the module first and passes that module's own
// organization, so the scope here is a structural assertion rather than an
// authorization decision: the scan returned belongs to the module that was
// looked up, and cannot be one that merely shares a version id.
func (r *ModuleScanRepository) GetLatestScan(ctx context.Context, moduleVersionID string, scope OrgScope) (*models.ModuleScan, error) {
	// GUARD scan-latest-tenant-scope (issue #783, sibling axis).
	q := `
		SELECT s.id, s.module_version_id, s.scanner, s.scanner_version, s.expected_version,
		       s.status, s.scanned_at, s.critical_count, s.high_count, s.medium_count, s.low_count,
		       s.raw_results, s.error_message, s.execution_log, s.created_at, s.updated_at
		FROM module_version_scans s
		JOIN module_versions mv ON mv.id = s.module_version_id
		JOIN modules m ON m.id = mv.module_id
		WHERE s.module_version_id = $1
	`
	args := []interface{}{moduleVersionID}
	clause, scopeArgs := scope.SQL("m.organization_id", len(args)+1)
	// #nosec G202 -- clause comes from OrgScope.SQL; see GetScanByID.
	q += " AND " + clause + " ORDER BY s.created_at DESC LIMIT 1"
	args = append(args, scopeArgs...)
	s := &models.ModuleScan{}
	var rawResults []byte
	err := r.db.QueryRowContext(ctx, q, args...).Scan(
		&s.ID, &s.ModuleVersionID, &s.Scanner, &s.ScannerVersion, &s.ExpectedVersion,
		&s.Status, &s.ScannedAt, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount,
		&rawResults, &s.ErrorMessage, &s.ExecutionLog, &s.CreatedAt, &s.UpdatedAt,
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

// GetScanByID returns a single scan record by its primary key, or nil if not found.
// GetScanByID fetches one scan, bound to the caller's tenancy.
//
// module_version_scans has no organization_id of its own -- it is transitively
// organization-owned through module_versions -> modules.organization_id -- so
// the predicate is a join rather than a column comparison. Before this took a
// scope it fetched purely by primary key, and any scanning:read holder could
// read another tenant's vulnerability findings by id (#783). scanning:read is
// granted by the seeded devops and auditor role templates through membership in
// a SINGLE organization, so that needed no platform authority at all.
//
// The scope is a required parameter rather than an optional filter: the zero
// value selects nothing, so a caller that forgets tenancy gets no row instead of
// every tenant's. That is the same shape the audit accessors took in #128, and
// the reason it lives in the accessor rather than the handler is #719 -- the
// by-id, list and export axes of that class drifted apart precisely because
// each re-implemented the predicate.
func (r *ModuleScanRepository) GetScanByID(ctx context.Context, scanID string, scope OrgScope) (*models.ModuleScan, error) {
	// GUARD scan-byid-tenant-scope (issue #783).
	q := `
		SELECT s.id, s.module_version_id, s.scanner, s.scanner_version, s.expected_version,
		       s.status, s.scanned_at, s.critical_count, s.high_count, s.medium_count, s.low_count,
		       s.raw_results, s.error_message, s.execution_log, s.created_at, s.updated_at
		FROM module_version_scans s
		JOIN module_versions mv ON mv.id = s.module_version_id
		JOIN modules m ON m.id = mv.module_id
		WHERE s.id = $1
	`
	args := []interface{}{scanID}
	clause, scopeArgs := scope.SQL("m.organization_id", len(args)+1)
	// #nosec G202 -- clause comes from OrgScope.SQL: "TRUE", "FALSE", or a fixed
	// template over an internal column constant and a $N placeholder. Scope
	// values travel as query arguments and are never interpolated.
	q += " AND " + clause
	args = append(args, scopeArgs...)
	s := &models.ModuleScan{}
	var rawResults []byte
	err := r.db.QueryRowContext(ctx, q, args...).Scan(
		&s.ID, &s.ModuleVersionID, &s.Scanner, &s.ScannerVersion, &s.ExpectedVersion,
		&s.Status, &s.ScannedAt, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount,
		&rawResults, &s.ErrorMessage, &s.ExecutionLog, &s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get scan by id: %w", err)
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
