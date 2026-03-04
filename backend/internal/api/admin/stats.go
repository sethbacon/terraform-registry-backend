// stats.go implements handlers for aggregating and serving dashboard statistics and download metrics.
package admin

import (
	"net/http"
	"time"

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
	Modules         ModuleStats         `json:"modules"`
	Providers       ProviderStats       `json:"providers"`
	Users           int64               `json:"users"`
	Organizations   int64               `json:"organizations"`
	Downloads       int64               `json:"downloads"`
	SCMProviders    int64               `json:"scm_providers"`
	BinaryMirrors   BinaryMirrorStats   `json:"binary_mirrors"`
	ProviderMirrors ProviderMirrorStats `json:"provider_mirrors"`
	RecentSyncs     []RecentSyncEntry   `json:"recent_syncs"`
}

// ModuleSystemCount is a count of modules for a single system (provider).
type ModuleSystemCount struct {
	System string `json:"system"`
	Count  int64  `json:"count"`
}

// ModuleStats represents module-specific statistics
type ModuleStats struct {
	Total     int64               `json:"total"`
	Versions  int64               `json:"versions"`
	Downloads int64               `json:"downloads"`
	BySystem  []ModuleSystemCount `json:"by_system"`
}

// ProviderStats represents provider-specific statistics with mirroring breakdown
type ProviderStats struct {
	Total            int64 `json:"total"`
	Manual           int64 `json:"manual"`
	Mirrored         int64 `json:"mirrored"`
	TotalVersions    int64 `json:"total_versions"`
	ManualVersions   int64 `json:"manual_versions"`
	MirroredVersions int64 `json:"mirrored_versions"`
	Downloads        int64 `json:"downloads"`
}

// BinaryToolCount is synced platform count for a single tool (terraform/opentofu).
type BinaryToolCount struct {
	Tool      string `json:"tool"`
	Platforms int64  `json:"platforms"`
}

// BinaryMirrorStats summarises terraform binary mirror health.
type BinaryMirrorStats struct {
	Total     int64             `json:"total"`
	Healthy   int64             `json:"healthy"`   // last_sync_status = 'success' or never synced but enabled
	Failed    int64             `json:"failed"`    // last_sync_status = 'failed'
	Syncing   int64             `json:"syncing"`   // last_sync_status = 'running'
	Platforms int64             `json:"platforms"` // total synced platform binaries
	Downloads int64             `json:"downloads"` // total binary downloads served
	ByTool    []BinaryToolCount `json:"by_tool"`
}

// ProviderMirrorStats summarises provider network mirror health.
type ProviderMirrorStats struct {
	Total   int64 `json:"total"`
	Healthy int64 `json:"healthy"`
	Failed  int64 `json:"failed"`
}

// RecentSyncEntry is a unified sync event from either mirror type.
type RecentSyncEntry struct {
	MirrorName      string     `json:"mirror_name"`
	MirrorType      string     `json:"mirror_type"` // "binary" | "provider"
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	VersionsSynced  int        `json:"versions_synced"`
	PlatformsSynced int        `json:"platforms_synced"`
	TriggeredBy     string     `json:"triggered_by"`
}

// @Summary      Get dashboard statistics
// @Description  Returns aggregated statistics for the admin dashboard including module, provider, user, organization, download, SCM provider, and mirror health counts.
// @Tags         Stats
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  DashboardStats
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/stats/dashboard [get]
// GetDashboardStats returns dashboard statistics using a single database round-trip.
func (h *StatsHandler) GetDashboardStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Core counts — single round-trip.
	query := `
		SELECT
			(SELECT COUNT(*) FROM modules) AS module_count,
			(SELECT COUNT(*) FROM module_versions) AS module_version_count,
			(SELECT COALESCE(SUM(download_count), 0) FROM module_versions) AS module_downloads,
			(SELECT COUNT(*) FROM providers) AS provider_count,
			(SELECT COUNT(*) FROM provider_versions) AS provider_version_count,
			(SELECT COALESCE(SUM(download_count), 0) FROM provider_platforms) AS provider_downloads,
			(SELECT COUNT(*) FROM users) AS user_count,
			(SELECT COUNT(*) FROM organizations) AS org_count
	`

	var stats DashboardStats

	err := h.db.QueryRowContext(ctx, query).Scan(
		&stats.Modules.Total,
		&stats.Modules.Versions,
		&stats.Modules.Downloads,
		&stats.Providers.Total,
		&stats.Providers.TotalVersions,
		&stats.Providers.Downloads,
		&stats.Users,
		&stats.Organizations,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load dashboard statistics"})
		return
	}
	stats.Downloads = stats.Modules.Downloads + stats.Providers.Downloads

	// Optional tables — graceful fallback to zero if migrations haven't run.
	_ = h.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT provider_id) FROM mirrored_providers").Scan(&stats.Providers.Mirrored)
	_ = h.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT provider_version_id) FROM mirrored_provider_versions").Scan(&stats.Providers.MirroredVersions)
	_ = h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scm_providers").Scan(&stats.SCMProviders)

	stats.Providers.Manual = stats.Providers.Total - stats.Providers.Mirrored
	stats.Providers.ManualVersions = stats.Providers.TotalVersions - stats.Providers.MirroredVersions

	// Module breakdown by system — top 8, optional.
	stats.Modules.BySystem = []ModuleSystemCount{}
	if sysRows, sysErr := h.db.QueryContext(ctx, `
		SELECT system, COUNT(*) AS count
		FROM modules
		GROUP BY system
		ORDER BY count DESC
		LIMIT 8
	`); sysErr == nil {
		defer sysRows.Close()
		for sysRows.Next() {
			var entry ModuleSystemCount
			if scanErr := sysRows.Scan(&entry.System, &entry.Count); scanErr == nil {
				stats.Modules.BySystem = append(stats.Modules.BySystem, entry)
			}
		}
	}

	// Binary mirror health (terraform_mirror_configs table).
	_ = h.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE last_sync_status = 'success' OR last_sync_status IS NULL) AS healthy,
			COUNT(*) FILTER (WHERE last_sync_status = 'failed') AS failed,
			COUNT(*) FILTER (WHERE last_sync_status = 'running') AS syncing
		FROM terraform_mirror_configs
		WHERE enabled = true
	`).Scan(
		&stats.BinaryMirrors.Total,
		&stats.BinaryMirrors.Healthy,
		&stats.BinaryMirrors.Failed,
		&stats.BinaryMirrors.Syncing,
	)
	_ = h.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM terraform_version_platforms p
		JOIN terraform_versions v ON v.id = p.version_id
		JOIN terraform_mirror_configs c ON c.id = v.config_id
		WHERE p.sync_status = 'synced' AND c.enabled = true
	`).Scan(&stats.BinaryMirrors.Platforms)
	_ = h.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(download_count), 0) FROM terraform_version_platforms
	`).Scan(&stats.BinaryMirrors.Downloads)
	stats.Downloads += stats.BinaryMirrors.Downloads

	// Per-tool platform breakdown (terraform vs opentofu).
	stats.BinaryMirrors.ByTool = []BinaryToolCount{}
	if toolRows, toolErr := h.db.QueryContext(ctx, `
		SELECT c.tool, COUNT(p.id) AS platforms
		FROM terraform_version_platforms p
		JOIN terraform_versions v ON v.id = p.version_id
		JOIN terraform_mirror_configs c ON c.id = v.config_id
		WHERE p.sync_status = 'synced' AND c.enabled = true
		GROUP BY c.tool
		ORDER BY platforms DESC
	`); toolErr == nil {
		defer toolRows.Close()
		for toolRows.Next() {
			var entry BinaryToolCount
			if scanErr := toolRows.Scan(&entry.Tool, &entry.Platforms); scanErr == nil {
				stats.BinaryMirrors.ByTool = append(stats.BinaryMirrors.ByTool, entry)
			}
		}
	}

	// Provider mirror health (mirror_configurations table).
	_ = h.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE last_sync_status = 'success' OR last_sync_status IS NULL) AS healthy,
			COUNT(*) FILTER (WHERE last_sync_status = 'failed') AS failed
		FROM mirror_configurations
		WHERE enabled = true
	`).Scan(
		&stats.ProviderMirrors.Total,
		&stats.ProviderMirrors.Healthy,
		&stats.ProviderMirrors.Failed,
	)

	// Recent sync activity — last 8 entries unified across both mirror types.
	recentRows, recentErr := h.db.QueryContext(ctx, `
		SELECT mirror_name, mirror_type, status, started_at, completed_at,
		       versions_synced, platforms_synced, triggered_by
		FROM (
			SELECT
				c.name            AS mirror_name,
				'binary'          AS mirror_type,
				h.status,
				h.started_at,
				h.completed_at,
				h.versions_synced,
				h.platforms_synced,
				h.triggered_by
			FROM terraform_sync_history h
			JOIN terraform_mirror_configs c ON c.id = h.config_id
			ORDER BY h.started_at DESC
			LIMIT 8
		) binary_syncs
		UNION ALL
		SELECT mirror_name, mirror_type, status, started_at, completed_at,
		       versions_synced, platforms_synced, triggered_by
		FROM (
			SELECT
				c.name                        AS mirror_name,
				'provider'                    AS mirror_type,
				h.status,
				h.started_at,
				h.completed_at,
				COALESCE(h.providers_synced, 0) AS versions_synced,
				0                             AS platforms_synced,
				'scheduler'                   AS triggered_by
			FROM mirror_sync_history h
			JOIN mirror_configurations c ON c.id = h.mirror_config_id
			ORDER BY h.started_at DESC
			LIMIT 8
		) provider_syncs
		ORDER BY started_at DESC
		LIMIT 8
	`)
	if recentErr == nil {
		defer recentRows.Close()
		for recentRows.Next() {
			var entry RecentSyncEntry
			if scanErr := recentRows.Scan(
				&entry.MirrorName,
				&entry.MirrorType,
				&entry.Status,
				&entry.StartedAt,
				&entry.CompletedAt,
				&entry.VersionsSynced,
				&entry.PlatformsSynced,
				&entry.TriggeredBy,
			); scanErr == nil {
				stats.RecentSyncs = append(stats.RecentSyncs, entry)
			}
		}
	}
	if stats.RecentSyncs == nil {
		stats.RecentSyncs = []RecentSyncEntry{}
	}

	c.JSON(http.StatusOK, stats)
}
