// org_quota_repository.go is the persistence layer for per-organization quota
// limits and daily usage counters. The admin dashboard endpoint composes both
// into a QuotaStatus row per org.
//
// Read-only here: this PR ships the READ endpoint that drives the frontend
// quota dashboard. The enforcement middleware (429 + X-Quota-Reset header)
// and the admin "set per-org limit" endpoint are deliberately out of scope
// to keep this PR reviewable.
package repositories

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

// OrgQuotaRepository reads quota and usage rows.
type OrgQuotaRepository struct {
	db *sqlx.DB
}

// NewOrgQuotaRepository constructs an OrgQuotaRepository.
func NewOrgQuotaRepository(db *sqlx.DB) *OrgQuotaRepository {
	return &OrgQuotaRepository{db: db}
}

// quotaStatusRow is the joined org/limit/today shape returned by the SQL below.
type quotaStatusRow struct {
	OrganizationID    string `db:"organization_id"`
	StorageBytesLimit int64  `db:"storage_bytes_limit"`
	PublishesPerDay   int    `db:"publishes_per_day"`
	DownloadsPerDay   int    `db:"downloads_per_day"`
	StorageBytesUsed  int64  `db:"storage_bytes_used"`
	PublishesToday    int    `db:"publishes_today"`
	DownloadsToday    int    `db:"downloads_today"`
}

// ListQuotaStatuses returns one QuotaStatus per organization. If orgID is non-empty,
// only that org's row is returned. Orgs with no quota row default to 0 (unlimited)
// for all limits. Orgs with no usage row default to 0 today.
//
// The query LEFT JOINs from organizations so that every org appears in the result
// even if it has never had a quota row written or any usage recorded today.
func (r *OrgQuotaRepository) ListQuotaStatuses(ctx context.Context, orgID string) ([]models.QuotaStatus, error) {
	query := `
		SELECT
			o.id::text AS organization_id,
			COALESCE(q.storage_bytes_limit, 0) AS storage_bytes_limit,
			COALESCE(q.publishes_per_day, 0)   AS publishes_per_day,
			COALESCE(q.downloads_per_day, 0)   AS downloads_per_day,
			COALESCE(u.storage_bytes_used, 0)  AS storage_bytes_used,
			COALESCE(u.publishes_today, 0)     AS publishes_today,
			COALESCE(u.downloads_today, 0)     AS downloads_today
		FROM organizations o
		LEFT JOIN org_quotas q       ON q.organization_id = o.id
		LEFT JOIN org_quota_usage u  ON u.organization_id = o.id AND u.date = CURRENT_DATE
	`
	args := []any{}
	if orgID != "" {
		query += " WHERE o.id::text = $1"
		args = append(args, orgID)
	}
	query += " ORDER BY o.id"

	var rows []quotaStatusRow
	if err := r.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, fmt.Errorf("list quota statuses: %w", err)
	}

	out := make([]models.QuotaStatus, 0, len(rows))
	for _, row := range rows {
		out = append(out, models.QuotaStatus{
			OrganizationID:    row.OrganizationID,
			StorageBytesLimit: row.StorageBytesLimit,
			StorageBytesUsed:  row.StorageBytesUsed,
			StorageRatio:      ratio(row.StorageBytesUsed, row.StorageBytesLimit),
			PublishesPerDay:   row.PublishesPerDay,
			PublishesToday:    row.PublishesToday,
			PublishRatio:      ratio(int64(row.PublishesToday), int64(row.PublishesPerDay)),
			DownloadsPerDay:   row.DownloadsPerDay,
			DownloadsToday:    row.DownloadsToday,
			DownloadRatio:     ratio(int64(row.DownloadsToday), int64(row.DownloadsPerDay)),
		})
	}
	return out, nil
}

// ratio returns used/limit as a float64. A limit of 0 means "unlimited" and
// produces a ratio of 0 (the dashboard treats 0 as "no warning state").
func ratio(used, limit int64) float64 {
	if limit <= 0 {
		return 0
	}
	return float64(used) / float64(limit)
}
