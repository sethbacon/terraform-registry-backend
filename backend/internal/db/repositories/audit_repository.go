// audit_repository.go implements AuditRepository, providing database queries for writing
// and retrieving audit log entries with support for filtered queries across users and resources.
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// AuditRepository handles audit log database operations
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository creates a new AuditRepository
func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// AuditFilters contains filters for querying audit logs
type AuditFilters struct {
	UserID         *string
	OrganizationID *string
	Action         *string
	ResourceType   *string
	StartDate      *time.Time
	EndDate        *time.Time
}

// CreateAuditLog creates a new audit log entry
func (r *AuditRepository) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	log.ID = uuid.New().String()
	log.CreatedAt = time.Now()

	// Marshal metadata to JSONB
	var metadataJSON []byte
	var err error
	if log.Metadata != nil {
		metadataJSON, err = json.Marshal(log.Metadata)
		if err != nil {
			return err
		}
	}

	query := `
		INSERT INTO audit_logs (id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err = r.db.ExecContext(ctx, query,
		log.ID,
		log.UserID,
		log.OrganizationID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		metadataJSON,
		log.IPAddress,
		log.CreatedAt,
	)

	return err
}

// ListAuditLogs retrieves audit logs with optional filters and pagination
func (r *AuditRepository) ListAuditLogs(ctx context.Context, filters AuditFilters, limit, offset int) ([]*models.AuditLog, int, error) {
	// Build query with filters
	countQuery := `SELECT COUNT(*) FROM audit_logs WHERE 1=1`
	query := `
		SELECT id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, created_at
		FROM audit_logs
		WHERE 1=1
	`

	args := make([]interface{}, 0)
	paramIndex := 1

	// Apply filters
	if filters.UserID != nil {
		countQuery += fmt.Sprintf(` AND user_id = $%d`, paramIndex)
		query += fmt.Sprintf(` AND user_id = $%d`, paramIndex)
		args = append(args, *filters.UserID)
		paramIndex++
	}

	if filters.OrganizationID != nil {
		countQuery += fmt.Sprintf(` AND organization_id = $%d`, paramIndex)
		query += fmt.Sprintf(` AND organization_id = $%d`, paramIndex)
		args = append(args, *filters.OrganizationID)
		paramIndex++
	}

	if filters.Action != nil {
		countQuery += fmt.Sprintf(` AND action = $%d`, paramIndex)
		query += fmt.Sprintf(` AND action = $%d`, paramIndex)
		args = append(args, *filters.Action)
		paramIndex++
	}

	if filters.ResourceType != nil {
		countQuery += fmt.Sprintf(` AND resource_type = $%d`, paramIndex)
		query += fmt.Sprintf(` AND resource_type = $%d`, paramIndex)
		args = append(args, *filters.ResourceType)
		paramIndex++
	}

	if filters.StartDate != nil {
		countQuery += fmt.Sprintf(` AND created_at >= $%d`, paramIndex)
		query += fmt.Sprintf(` AND created_at >= $%d`, paramIndex)
		args = append(args, *filters.StartDate)
		paramIndex++
	}

	if filters.EndDate != nil {
		countQuery += fmt.Sprintf(` AND created_at <= $%d`, paramIndex)
		query += fmt.Sprintf(` AND created_at <= $%d`, paramIndex)
		args = append(args, *filters.EndDate)
		paramIndex++
	}

	// Get total count
	var total int
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Add ordering and pagination
	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, paramIndex, paramIndex+1)
	args = append(args, limit, offset)

	// Execute query
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := make([]*models.AuditLog, 0)
	for rows.Next() {
		log := &models.AuditLog{}
		var metadataJSON []byte

		err := rows.Scan(
			&log.ID,
			&log.UserID,
			&log.OrganizationID,
			&log.Action,
			&log.ResourceType,
			&log.ResourceID,
			&metadataJSON,
			&log.IPAddress,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}

		// Unmarshal metadata from JSONB
		if metadataJSON != nil {
			err = json.Unmarshal(metadataJSON, &log.Metadata)
			if err != nil {
				return nil, 0, err
			}
		}

		logs = append(logs, log)
	}

	return logs, total, rows.Err()
}

// GetAuditLog retrieves a single audit log entry by ID
func (r *AuditRepository) GetAuditLog(ctx context.Context, logID string) (*models.AuditLog, error) {
	query := `
		SELECT id, user_id, organization_id, action, resource_type, resource_id, metadata, ip_address, created_at
		FROM audit_logs
		WHERE id = $1
	`

	log := &models.AuditLog{}
	var metadataJSON []byte

	err := r.db.QueryRowContext(ctx, query, logID).Scan(
		&log.ID,
		&log.UserID,
		&log.OrganizationID,
		&log.Action,
		&log.ResourceType,
		&log.ResourceID,
		&metadataJSON,
		&log.IPAddress,
		&log.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	// Unmarshal metadata from JSONB
	if metadataJSON != nil {
		err = json.Unmarshal(metadataJSON, &log.Metadata)
		if err != nil {
			return nil, err
		}
	}

	return log, nil
}
