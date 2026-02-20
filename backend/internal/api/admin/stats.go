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
// GetDashboardStats returns dashboard statistics
func (h *StatsHandler) GetDashboardStats(c *gin.Context) {
	var stats DashboardStats

	// Get total modules
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM modules").Scan(&stats.Modules.Total); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count modules"})
		return
	}

	// Get total providers
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM providers").Scan(&stats.Providers.Total); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count providers"})
		return
	}

	// Get mirrored providers count
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(DISTINCT provider_id) FROM mirrored_providers").Scan(&stats.Providers.Mirrored); err != nil {
		// If table doesn't exist yet (before migration 011), just set to 0
		stats.Providers.Mirrored = 0
	}

	// Calculate manual providers
	stats.Providers.Manual = stats.Providers.Total - stats.Providers.Mirrored

	// Get total provider versions
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM provider_versions").Scan(&stats.Providers.TotalVersions); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count provider versions"})
		return
	}

	// Get mirrored provider versions count
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(DISTINCT provider_version_id) FROM mirrored_provider_versions").Scan(&stats.Providers.MirroredVersions); err != nil {
		// If table doesn't exist yet (before migration 011), just set to 0
		stats.Providers.MirroredVersions = 0
	}

	// Calculate manual provider versions
	stats.Providers.ManualVersions = stats.Providers.TotalVersions - stats.Providers.MirroredVersions

	// Get total users
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM users").Scan(&stats.Users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count users"})
		return
	}

	// Get total organizations
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM organizations").Scan(&stats.Organizations); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count organizations"})
		return
	}

	// Get total SCM providers
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COUNT(*) FROM scm_providers").Scan(&stats.SCMProviders); err != nil {
		// If table doesn't exist yet, just set to 0
		stats.SCMProviders = 0
	}

	// Get total downloads (sum of module version downloads and provider platform downloads)
	var moduleDownloads, providerDownloads int64
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COALESCE(SUM(download_count), 0) FROM module_versions").Scan(&moduleDownloads); err != nil {
		moduleDownloads = 0
	}
	if err := h.db.QueryRowContext(c.Request.Context(), "SELECT COALESCE(SUM(download_count), 0) FROM provider_platforms").Scan(&providerDownloads); err != nil {
		providerDownloads = 0
	}
	stats.Downloads = moduleDownloads + providerDownloads

	c.JSON(http.StatusOK, stats)
}
