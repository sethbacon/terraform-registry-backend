// stats.go implements handlers for aggregating and serving dashboard statistics and download metrics.
package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// StatsHandler handles stats-related API requests
type StatsHandler struct {
	db *sqlx.DB
}

// NewStatsHandler creates a new stats handler
func NewStatsHandler(database *sqlx.DB) *StatsHandler {
	return &StatsHandler{
		db: database,
	}
}

// DashboardStats represents the response for dashboard statistics
type DashboardStats struct {
	Modules       ModuleStats   `json:"modules"`
	Providers     ProviderStats `json:"providers"`
	Users         int64         `json:"users"`
	Organizations int64         `json:"organizations"`
	Downloads     int64         `json:"downloads"`
	SCMProviders  int64         `json:"scm_providers"`
}

// ModuleStats represents module-specific statistics
type ModuleStats struct {
	Total int64 `json:"total"`
}

// ProviderStats represents provider-specific statistics with mirroring breakdown
type ProviderStats struct {
	Total            int64 `json:"total"`
	Manual           int64 `json:"manual"`
	Mirrored         int64 `json:"mirrored"`
	TotalVersions    int64 `json:"total_versions"`
	ManualVersions   int64 `json:"manual_versions"`
	MirroredVersions int64 `json:"mirrored_versions"`
}

// @Summary      Get dashboard statistics
// @Description  Returns aggregated statistics for the admin dashboard including module, provider, user, organization, download, and SCM provider counts.
// @Tags         Stats
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  DashboardStats
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/stats/dashboard [get]
// GetDashboardStats returns dashboard statistics using a single database round-trip.
func (h *StatsHandler) GetDashboardStats(c *gin.Context) {
	// Combine all counts into a single query using sub-selects.
	// Tables that may not exist yet (mirrored_providers, mirrored_provider_versions,
	// scm_providers) are queried via a function that returns 0 on error so the
	// entire query doesn't fail if a migration hasn't run yet.
	query := `
		SELECT
			(SELECT COUNT(*) FROM modules) AS module_count,
			(SELECT COUNT(*) FROM providers) AS provider_count,
			(SELECT COUNT(*) FROM provider_versions) AS provider_version_count,
			(SELECT COUNT(*) FROM users) AS user_count,
			(SELECT COUNT(*) FROM organizations) AS org_count,
			(SELECT COALESCE(SUM(download_count), 0) FROM module_versions) AS module_downloads,
			(SELECT COALESCE(SUM(download_count), 0) FROM provider_platforms) AS provider_downloads
	`

	var stats DashboardStats
	var moduleDownloads, providerDownloads int64

	err := h.db.QueryRowContext(c.Request.Context(), query).Scan(
		&stats.Modules.Total,
		&stats.Providers.Total,
		&stats.Providers.TotalVersions,
		&stats.Users,
		&stats.Organizations,
		&moduleDownloads,
		&providerDownloads,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load dashboard statistics"})
		return
	}
	stats.Downloads = moduleDownloads + providerDownloads

	// Mirrored counts come from tables that may not exist before certain migrations,
	// so query them separately with graceful fallback to 0.
	_ = h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(DISTINCT provider_id) FROM mirrored_providers").Scan(&stats.Providers.Mirrored)
	_ = h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(DISTINCT provider_version_id) FROM mirrored_provider_versions").Scan(&stats.Providers.MirroredVersions)
	_ = h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM scm_providers").Scan(&stats.SCMProviders)

	stats.Providers.Manual = stats.Providers.Total - stats.Providers.Mirrored
	stats.Providers.ManualVersions = stats.Providers.TotalVersions - stats.Providers.MirroredVersions

	c.JSON(http.StatusOK, stats)
}
