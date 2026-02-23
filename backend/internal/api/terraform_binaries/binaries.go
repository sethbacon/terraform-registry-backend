// Package terraform_binaries implements the public HTTP handlers for the Terraform
// binary mirror feature.  These endpoints are intentionally unauthenticated — they
// allow any Terraform or OpenTofu client/operator to discover and download binaries
// that have been synced by the background mirror job.
//
// Route layout (all scoped to a named mirror config):
//
//	GET /terraform/binaries/:name/versions                     — list all synced versions
//	GET /terraform/binaries/:name/versions/latest              — resolve the current latest version
//	GET /terraform/binaries/:name/versions/:version            — version detail + platform list
//	GET /terraform/binaries/:name/versions/:version/:os/:arch  — get signed download URL
package terraform_binaries

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
	"github.com/terraform-registry/terraform-registry/internal/validation"
)

// Handler holds the dependencies for all Terraform binary public endpoints.
type Handler struct {
	repo           *repositories.TerraformMirrorRepository
	storageBackend storage.Storage
}

// NewHandler creates a new Handler.
func NewHandler(repo *repositories.TerraformMirrorRepository, storageBackend storage.Storage) *Handler {
	return &Handler{repo: repo, storageBackend: storageBackend}
}

// resolveConfig looks up the mirror config by name from the :name path parameter.
// Returns the config and true on success; writes an HTTP error response and returns false on failure.
func (h *Handler) resolveConfig(c *gin.Context) (*models.TerraformMirrorConfig, bool) {
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Mirror name is required"})
		return nil, false
	}

	cfg, err := h.repo.GetByName(c.Request.Context(), name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up mirror"})
		return nil, false
	}
	if cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror not found: " + name})
		return nil, false
	}
	if !cfg.Enabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "Mirror is not enabled: " + name})
		return nil, false
	}

	return cfg, true
}

// ---- GET /terraform/binaries/:name/versions ----------------------------------------

// @Summary      List mirrored Terraform versions
// @Description  Returns all Terraform/OpenTofu versions that have been fully or partially synced by the named binary mirror.
// @Tags         TerraformBinaries
// @Produce      json
// @Param        name  path  string  true  "Mirror configuration name"
// @Success      200  {object}  models.TerraformVersionListResponse
// @Failure      404  {object}  map[string]interface{}  "Mirror not found or not enabled"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /terraform/binaries/{name}/versions [get]
func (h *Handler) ListVersions(c *gin.Context) {
	cfg, ok := h.resolveConfig(c)
	if !ok {
		return
	}

	versions, err := h.repo.ListVersions(c.Request.Context(), cfg.ID, true /* syncedOnly */)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list versions"})
		return
	}

	c.Header("Cache-Control", "public, max-age=300") // 5-minute public cache
	c.JSON(http.StatusOK, models.TerraformVersionListResponse{
		Versions:   versions,
		TotalCount: len(versions),
	})
}

// ---- GET /terraform/binaries/:name/versions/latest ---------------------------------

// @Summary      Get latest mirrored Terraform version
// @Description  Returns the latest stable Terraform/OpenTofu version available in the named binary mirror.
// @Tags         TerraformBinaries
// @Produce      json
// @Param        name  path  string  true  "Mirror configuration name"
// @Success      200  {object}  models.TerraformVersion
// @Failure      404  {object}  map[string]interface{}  "Mirror not found or no latest version"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /terraform/binaries/{name}/versions/latest [get]
func (h *Handler) GetLatestVersion(c *gin.Context) {
	cfg, ok := h.resolveConfig(c)
	if !ok {
		return
	}

	version, err := h.repo.GetLatestVersion(c.Request.Context(), cfg.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get latest version"})
		return
	}
	if version == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No latest version available — run a sync first"})
		return
	}

	// Attach platforms
	platforms, err := h.repo.ListPlatformsForVersion(c.Request.Context(), version.ID)
	if err == nil {
		version.Platforms = platforms
	}

	c.Header("Cache-Control", "public, max-age=60") // 1-minute cache for latest
	c.JSON(http.StatusOK, version)
}

// ---- GET /terraform/binaries/:name/versions/:version --------------------------------

// @Summary      Get specific mirrored Terraform version
// @Description  Returns metadata and platform list for a specific version in the named binary mirror.
// @Tags         TerraformBinaries
// @Produce      json
// @Param        name     path  string  true  "Mirror configuration name"
// @Param        version  path  string  true  "Terraform version (e.g. 1.9.0)"
// @Success      200  {object}  models.TerraformVersion
// @Failure      400  {object}  map[string]interface{}  "Invalid version format"
// @Failure      404  {object}  map[string]interface{}  "Mirror or version not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /terraform/binaries/{name}/versions/{version} [get]
func (h *Handler) GetVersion(c *gin.Context) {
	versionStr := c.Param("version")
	if err := validation.ValidateSemver(versionStr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []string{"Invalid version format — must be valid semantic versioning"}})
		return
	}

	cfg, ok := h.resolveConfig(c)
	if !ok {
		return
	}

	version, err := h.repo.GetVersionByString(c.Request.Context(), cfg.ID, versionStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query version"})
		return
	}
	if version == nil || version.SyncStatus == "pending" {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Version not found or not yet synced"}})
		return
	}

	// Attach only synced platforms
	platforms, err := h.repo.ListPlatformsForVersion(c.Request.Context(), version.ID)
	if err == nil {
		synced := platforms[:0]
		for _, p := range platforms {
			if p.SyncStatus == "synced" {
				synced = append(synced, p)
			}
		}
		version.Platforms = synced
	}

	c.Header("Cache-Control", "public, max-age=300")
	c.JSON(http.StatusOK, version)
}

// ---- GET /terraform/binaries/:name/versions/:version/:os/:arch ---------------------

// @Summary      Download Terraform binary
// @Description  Returns a signed download URL for the requested Terraform binary. The URL is valid for 15 minutes. Increments the terraform_binary_downloads_total Prometheus counter.
// @Tags         TerraformBinaries
// @Produce      json
// @Param        name     path  string  true  "Mirror configuration name"
// @Param        version  path  string  true  "Terraform version (e.g. 1.9.0)"
// @Param        os       path  string  true  "Operating system (e.g. linux, darwin, windows)"
// @Param        arch     path  string  true  "CPU architecture (e.g. amd64, arm64)"
// @Success      200  {object}  models.TerraformBinaryDownloadResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid version or platform"
// @Failure      404  {object}  map[string]interface{}  "Mirror, version, or platform not found"
// @Failure      503  {object}  map[string]interface{}  "Binary not yet available (sync pending)"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /terraform/binaries/{name}/versions/{version}/{os}/{arch} [get]
func (h *Handler) DownloadBinary(c *gin.Context) {
	versionStr := c.Param("version")
	osStr := c.Param("os")
	archStr := c.Param("arch")

	// Validate inputs
	if err := validation.ValidateSemver(versionStr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []string{"Invalid version format — must be valid semantic versioning"}})
		return
	}
	if err := validation.ValidatePlatform(osStr, archStr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"errors": []string{err.Error()}})
		return
	}

	cfg, ok := h.resolveConfig(c)
	if !ok {
		return
	}

	// Look up version
	version, err := h.repo.GetVersionByString(c.Request.Context(), cfg.ID, versionStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query version"})
		return
	}
	if version == nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Version not found"}})
		return
	}

	// Look up platform
	platform, err := h.repo.GetPlatform(c.Request.Context(), version.ID, osStr, archStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query platform"})
		return
	}
	if platform == nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Platform not found for this version"}})
		return
	}

	// Ensure the binary has been synced to storage
	if platform.SyncStatus != "synced" || platform.StorageKey == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":       "Binary not yet available — sync is in progress or has not been triggered",
			"sync_status": platform.SyncStatus,
		})
		return
	}

	// Generate pre-signed download URL (15-minute TTL)
	downloadURL, err := h.storageBackend.GetURL(c.Request.Context(), *platform.StorageKey, 15*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate download URL"})
		return
	}

	// Increment Prometheus download counter
	telemetry.TerraformBinaryDownloadsTotal.WithLabelValues(versionStr, osStr, archStr).Inc()

	c.JSON(http.StatusOK, models.TerraformBinaryDownloadResponse{
		OS:          platform.OS,
		Arch:        platform.Arch,
		Version:     version.Version,
		Filename:    platform.Filename,
		SHA256:      platform.SHA256,
		DownloadURL: downloadURL,
	})
}
