// serve.go handles direct file serving of module and provider archives from local storage backends.
package modules

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// ServeFileHandler serves a module archive file.
// @Summary      Download module archive
// @Description  Streams a module version archive file
// @Tags         Modules
// @Param        namespace  path  string  true  "Namespace"
// @Param        name       path  string  true  "Module name"
// @Param        provider   path  string  true  "Provider"
// @Param        version    path  string  true  "Version"
// @Produce      application/zip
// @Success      200
// @Failure      404  {object}  map[string]interface{}
// @Router       /api/v1/modules/{namespace}/{name}/{provider}/{version}/download [get]
// ServeFileHandler handles direct file serving for local storage
// Implements: GET /v1/files/*filepath
// Only used when local storage has ServeDirectly: true
func ServeFileHandler(storageBackend storage.Storage, cfg *config.Config, db *sql.DB, auditRepo *repositories.AuditRepository) gin.HandlerFunc {
	var providerRepo *repositories.ProviderRepository
	var orgRepo *repositories.OrganizationRepository
	if db != nil {
		providerRepo = repositories.NewProviderRepository(db)
		orgRepo = repositories.NewOrganizationRepository(db)
	}

	return func(c *gin.Context) {
		// Get file path from URL
		filePath := c.Param("filepath")
		if filePath == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "File path is required",
			})
			return
		}

		// Remove leading slash if present
		if len(filePath) > 0 && filePath[0] == '/' {
			filePath = filePath[1:]
		}

		// Check if file exists
		exists, err := storageBackend.Exists(c.Request.Context(), filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check file existence",
			})
			return
		}
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "File not found",
			})
			return
		}

		// Get file metadata
		metadata, err := storageBackend.GetMetadata(c.Request.Context(), filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get file metadata",
			})
			return
		}

		// Download file from storage
		reader, err := storageBackend.Download(c.Request.Context(), filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to read file",
			})
			return
		}
		defer reader.Close()

		// Track provider downloads: path is providers/{namespace}/{type}/{version}/{os}/{arch}/{file}
		if providerRepo != nil {
			if ns, pt, ver, osName, arch, ok := parseProviderFilePath(filePath); ok {
				go trackProviderDownload(providerRepo, orgRepo, ns, pt, ver, osName, arch)
				telemetry.ProviderDownloadsTotal.WithLabelValues(ns, pt, osName, arch).Inc()
			}
		}

		// Audit log the file download event asynchronously
		if auditRepo != nil {
			resourceType := "file"
			if strings.HasPrefix(filePath, "providers/") {
				resourceType = "provider"
			} else if strings.HasPrefix(filePath, "modules/") {
				resourceType = "module"
			}
			action := "GET " + c.Request.URL.Path
			ip := c.ClientIP()
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := auditRepo.CreateAuditLog(ctx, &models.AuditLog{
					Action:       action,
					ResourceType: &resourceType,
					IPAddress:    &ip,
				}); err != nil {
					slog.Error("failed to write audit log for file download", "error", err, "action", action)
				}
			}()
		}

		// Set response headers
		c.Header("Content-Type", "application/gzip")
		c.Header("Content-Disposition", "attachment")
		c.Header("X-Checksum-SHA256", metadata.Checksum)

		// Stream file to client
		c.DataFromReader(http.StatusOK, metadata.Size, "application/gzip", reader, nil)
	}
}

// parseProviderFilePath extracts components from a provider file path of the form:
// providers/{namespace}/{type}/{version}/{os}/{arch}/{filename}
func parseProviderFilePath(path string) (namespace, providerType, version, os, arch string, ok bool) {
	parts := strings.Split(path, "/")
	if len(parts) < 7 || parts[0] != "providers" {
		return "", "", "", "", "", false
	}
	return parts[1], parts[2], parts[3], parts[4], parts[5], true
}

// trackProviderDownload looks up the provider platform and increments its download count.
func trackProviderDownload(providerRepo *repositories.ProviderRepository, orgRepo *repositories.OrganizationRepository, namespace, providerType, version, osName, arch string) {
	ctx := context.Background()
	org, err := orgRepo.GetDefaultOrganization(ctx)
	if err != nil || org == nil {
		return
	}
	provider, err := providerRepo.GetProvider(ctx, org.ID, namespace, providerType)
	if err != nil || provider == nil {
		return
	}
	pv, err := providerRepo.GetVersion(ctx, provider.ID, version)
	if err != nil || pv == nil {
		return
	}
	platforms, err := providerRepo.ListPlatforms(ctx, pv.ID)
	if err != nil {
		return
	}
	for _, p := range platforms {
		if p.OS == osName && p.Arch == arch {
			_ = providerRepo.IncrementDownloadCount(ctx, p.ID)
			return
		}
	}
}
