// scanning_admin.go implements admin endpoints for viewing scanning configuration and aggregate scan statistics.
package admin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// ScanningConfigResponse is the public view of the scanning config (no binary path).
type ScanningConfigResponse struct {
	Enabled           bool   `json:"enabled"`
	Tool              string `json:"tool"`
	ExpectedVersion   string `json:"expected_version,omitempty"`
	SeverityThreshold string `json:"severity_threshold"`
	Timeout           string `json:"timeout"`
	WorkerCount       int    `json:"worker_count"`
	ScanIntervalMins  int    `json:"scan_interval_mins"`
}

// ScanningStatsResponse aggregates scan counts by status and recent activity.
type ScanningStatsResponse struct {
	Total       int64             `json:"total"`
	Pending     int64             `json:"pending"`
	Scanning    int64             `json:"scanning"`
	Clean       int64             `json:"clean"`
	Findings    int64             `json:"findings"`
	Error       int64             `json:"error"`
	RecentScans []RecentScanEntry `json:"recent_scans"`
}

// RecentScanEntry summarises a single recent scan for the admin UI.
type RecentScanEntry struct {
	ID            string     `json:"id"`
	ModuleVersion string     `json:"module_version"`
	ModuleName    string     `json:"module_name"`
	Namespace     string     `json:"namespace"`
	System        string     `json:"system"`
	Scanner       string     `json:"scanner"`
	Status        string     `json:"status"`
	Critical      int        `json:"critical_count"`
	High          int        `json:"high_count"`
	Medium        int        `json:"medium_count"`
	Low           int        `json:"low_count"`
	ScannedAt     *time.Time `json:"scanned_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// @Summary      Get scanning configuration
// @Description  Returns the current security scanning configuration (read-only). Sensitive fields like binary_path are excluded. Requires admin scope.
// @Tags         Security Scanning
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  ScanningConfigResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Router       /api/v1/admin/scanning/config [get]
func GetScanningConfigHandler(cfg *config.ScanningConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := ScanningConfigResponse{
			Enabled:           cfg.Enabled,
			Tool:              cfg.Tool,
			ExpectedVersion:   cfg.ExpectedVersion,
			SeverityThreshold: cfg.SeverityThreshold,
			Timeout:           cfg.Timeout.String(),
			WorkerCount:       cfg.WorkerCount,
			ScanIntervalMins:  cfg.ScanIntervalMins,
		}
		c.JSON(http.StatusOK, resp)
	}
}

// @Summary      Get scanning statistics
// @Description  Returns aggregate scan counts by status and a list of recent scans. Requires admin scope.
// @Tags         Security Scanning
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  ScanningStatsResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/scanning/stats [get]
func GetScanningStatsHandler(db *sqlx.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		var stats ScanningStatsResponse

		// Aggregate counts by status.
		err := db.QueryRowContext(ctx, `
			SELECT
				COUNT(*) AS total,
				COUNT(*) FILTER (WHERE status = 'pending') AS pending,
				COUNT(*) FILTER (WHERE status = 'scanning') AS scanning,
				COUNT(*) FILTER (WHERE status = 'clean') AS clean,
				COUNT(*) FILTER (WHERE status = 'findings') AS findings,
				COUNT(*) FILTER (WHERE status = 'error') AS error_count
			FROM module_version_scans
		`).Scan(
			&stats.Total,
			&stats.Pending,
			&stats.Scanning,
			&stats.Clean,
			&stats.Findings,
			&stats.Error,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query scan statistics"})
			return
		}

		// Recent scans — last 10, with module info joined.
		rows, err := db.QueryContext(ctx, `
			SELECT
				s.id, mv.version, m.name, m.namespace, m.system,
				s.scanner, s.status,
				s.critical_count, s.high_count, s.medium_count, s.low_count,
				s.scanned_at, s.created_at
			FROM module_version_scans s
			JOIN module_versions mv ON mv.id = s.module_version_id
			JOIN modules m ON m.id = mv.module_id
			ORDER BY s.updated_at DESC
			LIMIT 10
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query recent scans"})
			return
		}
		defer rows.Close()

		stats.RecentScans = []RecentScanEntry{}
		for rows.Next() {
			var entry RecentScanEntry
			if scanErr := rows.Scan(
				&entry.ID, &entry.ModuleVersion, &entry.ModuleName, &entry.Namespace, &entry.System,
				&entry.Scanner, &entry.Status,
				&entry.Critical, &entry.High, &entry.Medium, &entry.Low,
				&entry.ScannedAt, &entry.CreatedAt,
			); scanErr == nil {
				stats.RecentScans = append(stats.RecentScans, entry)
			}
		}

		c.JSON(http.StatusOK, stats)
	}
}
