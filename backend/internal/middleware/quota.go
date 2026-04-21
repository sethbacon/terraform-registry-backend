// Package middleware — quota.go enforces per-organization resource quotas.
// coverage:skip:requires-postgres
//
// The middleware checks current usage against configured limits and returns
// 429 Too Many Requests when a quota is exceeded. It also emits Prometheus
// metrics for quota utilization monitoring.
package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	quotaUtilization = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "registry_quota_utilization_ratio",
			Help: "Current quota utilization ratio per organization and resource type",
		},
		[]string{"org", "resource"},
	)

	quotaExceeded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "registry_quota_exceeded_total",
			Help: "Total number of requests rejected due to quota exceeded",
		},
		[]string{"org", "resource"},
	)
)

// QuotaChecker provides quota lookup and enforcement.
type QuotaChecker struct {
	db *sql.DB
}

// NewQuotaChecker creates a new QuotaChecker.
func NewQuotaChecker(db *sql.DB) *QuotaChecker {
	return &QuotaChecker{db: db}
}

// CheckPublishQuota is middleware that enforces the daily publish quota.
func (qc *QuotaChecker) CheckPublishQuota() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.GetString("organization_id")
		if orgID == "" {
			c.Next()
			return
		}

		exceeded, resetTime, err := qc.isPublishQuotaExceeded(c.Request.Context(), orgID)
		if err != nil {
			// On error, allow the request (fail open for availability)
			c.Next()
			return
		}

		if exceeded {
			quotaExceeded.WithLabelValues(orgID, "publishes").Inc()
			c.Header("X-Quota-Reset", resetTime.Format(time.RFC3339))
			c.Header("Retry-After", fmt.Sprintf("%d", int(time.Until(resetTime).Seconds())))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Daily publish quota exceeded",
				"quota_reset": resetTime.Format(time.RFC3339),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CheckDownloadQuota is middleware that enforces the daily download quota.
func (qc *QuotaChecker) CheckDownloadQuota() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := c.GetString("organization_id")
		if orgID == "" {
			c.Next()
			return
		}

		exceeded, resetTime, err := qc.isDownloadQuotaExceeded(c.Request.Context(), orgID)
		if err != nil {
			c.Next()
			return
		}

		if exceeded {
			quotaExceeded.WithLabelValues(orgID, "downloads").Inc()
			c.Header("X-Quota-Reset", resetTime.Format(time.RFC3339))
			c.Header("Retry-After", fmt.Sprintf("%d", int(time.Until(resetTime).Seconds())))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Daily download quota exceeded",
				"quota_reset": resetTime.Format(time.RFC3339),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// IncrementPublishCount records a publish against the organization's daily quota.
func (qc *QuotaChecker) IncrementPublishCount(ctx context.Context, orgID string) error {
	_, err := qc.db.ExecContext(ctx, `
		INSERT INTO org_quota_usage (organization_id, date, publishes_today)
		VALUES ($1, CURRENT_DATE, 1)
		ON CONFLICT (organization_id, date)
		DO UPDATE SET publishes_today = org_quota_usage.publishes_today + 1
	`, orgID)
	return err
}

// IncrementDownloadCount records a download against the organization's daily quota.
func (qc *QuotaChecker) IncrementDownloadCount(ctx context.Context, orgID string) error {
	_, err := qc.db.ExecContext(ctx, `
		INSERT INTO org_quota_usage (organization_id, date, downloads_today)
		VALUES ($1, CURRENT_DATE, 1)
		ON CONFLICT (organization_id, date)
		DO UPDATE SET downloads_today = org_quota_usage.downloads_today + 1
	`, orgID)
	return err
}

// UpdateStorageUsage updates the storage bytes used for an organization.
func (qc *QuotaChecker) UpdateStorageUsage(ctx context.Context, orgID string, deltaBytes int64) error {
	_, err := qc.db.ExecContext(ctx, `
		INSERT INTO org_quota_usage (organization_id, date, storage_bytes_used)
		VALUES ($1, CURRENT_DATE, $2)
		ON CONFLICT (organization_id, date)
		DO UPDATE SET storage_bytes_used = org_quota_usage.storage_bytes_used + $2
	`, orgID, deltaBytes)
	return err
}

// UpdateMetrics refreshes Prometheus quota utilization gauges for all orgs.
func (qc *QuotaChecker) UpdateMetrics(ctx context.Context) {
	rows, err := qc.db.QueryContext(ctx, `
		SELECT q.organization_id,
			   q.storage_bytes_limit, COALESCE(u.storage_bytes_used, 0),
			   q.publishes_per_day, COALESCE(u.publishes_today, 0),
			   q.downloads_per_day, COALESCE(u.downloads_today, 0)
		FROM org_quotas q
		LEFT JOIN org_quota_usage u ON u.organization_id = q.organization_id AND u.date = CURRENT_DATE
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var orgID string
		var storageLimit, storageUsed int64
		var publishLimit, publishUsed, downloadLimit, downloadUsed int

		if err := rows.Scan(&orgID, &storageLimit, &storageUsed,
			&publishLimit, &publishUsed, &downloadLimit, &downloadUsed); err != nil {
			continue
		}

		if storageLimit > 0 {
			quotaUtilization.WithLabelValues(orgID, "storage").Set(float64(storageUsed) / float64(storageLimit))
		}
		if publishLimit > 0 {
			quotaUtilization.WithLabelValues(orgID, "publishes").Set(float64(publishUsed) / float64(publishLimit))
		}
		if downloadLimit > 0 {
			quotaUtilization.WithLabelValues(orgID, "downloads").Set(float64(downloadUsed) / float64(downloadLimit))
		}
	}
}

func (qc *QuotaChecker) isPublishQuotaExceeded(ctx context.Context, orgID string) (bool, time.Time, error) {
	var limit, used int
	err := qc.db.QueryRowContext(ctx, `
		SELECT COALESCE(q.publishes_per_day, 0), COALESCE(u.publishes_today, 0)
		FROM org_quotas q
		LEFT JOIN org_quota_usage u ON u.organization_id = q.organization_id AND u.date = CURRENT_DATE
		WHERE q.organization_id = $1
	`, orgID).Scan(&limit, &used)
	if err != nil {
		return false, time.Time{}, err
	}

	if limit == 0 {
		return false, time.Time{}, nil // unlimited
	}

	resetTime := nextMidnightUTC()
	return used >= limit, resetTime, nil
}

func (qc *QuotaChecker) isDownloadQuotaExceeded(ctx context.Context, orgID string) (bool, time.Time, error) {
	var limit, used int
	err := qc.db.QueryRowContext(ctx, `
		SELECT COALESCE(q.downloads_per_day, 0), COALESCE(u.downloads_today, 0)
		FROM org_quotas q
		LEFT JOIN org_quota_usage u ON u.organization_id = q.organization_id AND u.date = CURRENT_DATE
		WHERE q.organization_id = $1
	`, orgID).Scan(&limit, &used)
	if err != nil {
		return false, time.Time{}, err
	}

	if limit == 0 {
		return false, time.Time{}, nil
	}

	resetTime := nextMidnightUTC()
	return used >= limit, resetTime, nil
}

func nextMidnightUTC() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
}
