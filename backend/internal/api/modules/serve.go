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
	"github.com/terraform-registry/terraform-registry/internal/middleware"
	"github.com/terraform-registry/terraform-registry/internal/safego"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/storage/urlsign"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
)

// ServeFileHandler serves a module or provider archive file directly from local storage.
// @Summary      Serve archive file from local storage
// @Description  Streams a stored archive file. Requires the `expires` and `sig` query parameters produced by the local storage backend's signed download URL; unsigned, forged or expired requests are rejected with 403. Path traversal sequences are rejected.
// @Tags         Files
// @Param        filepath   path   string  true  "Storage-relative file path"
// @Param        expires    query  string  true  "Signature expiry, unix seconds"
// @Param        sig        query  string  true  "URL signature"
// @Produce      application/octet-stream
// @Success      200
// @Failure      400  {object}  map[string]interface{}  "Invalid file path"
// @Failure      403  {object}  map[string]interface{}  "Invalid or expired download URL"
// @Failure      404  {object}  map[string]interface{}  "File not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /v1/files/{filepath} [get]
// ServeFileHandler handles direct file serving for local storage
// Implements: GET /v1/files/*filepath
// Only used when local storage has ServeDirectly: true
func ServeFileHandler(storageBackend storage.Storage, cfg *config.Config, db *sql.DB, auditRepo *repositories.AuditRepository) gin.HandlerFunc {
	var providerRepo *repositories.ProviderRepository
	if db != nil {
		providerRepo = repositories.NewProviderRepository(db)
	}

	return func(c *gin.Context) {
		// Get file path from URL
		filePath := c.Param("filepath")
		if filePath == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"errors": []string{"File path is required"},
			})
			return
		}

		// Remove leading slash if present
		if len(filePath) > 0 && filePath[0] == '/' {
			filePath = filePath[1:]
		}

		// Reject path traversal sequences. The local storage backend uses
		// filepath.Join which resolves ".." — block them here before any backend
		// call so that GET /v1/files/../../etc/passwd cannot escape the storage root.
		if strings.Contains(filePath, "..") || strings.Contains(filePath, "//") {
			c.JSON(http.StatusBadRequest, gin.H{
				"errors": []string{"Invalid file path"},
			})
			return
		}

		// AUTHORIZE THE FETCH (#973).
		//
		// This route has no authentication middleware -- not requireAuth, not
		// OptionalAuth -- and it streams whatever storage key it is handed.
		// Keys are structural and guessable, so before this check anyone who
		// could reach the deployment could enumerate every module archive and
		// terraform binary anonymously, and the fetch appeared nowhere as an
		// authorised download.
		//
		// The signature comes from LocalStorage.GetURL, which is the only thing
		// that produces these URLs. Verified BEFORE the approval gate and before
		// any storage call, so an unsigned request cannot use this handler to
		// probe which keys exist.
		//
		// filePath here is post-decode and post-leading-slash-strip -- the same
		// canonical storage key GetURL signed.
		if err := urlsign.Verify(
			filePath,
			c.Query(urlsign.ParamExpires),
			c.Query(urlsign.ParamSignature),
			time.Now(),
		); err != nil {
			// One response for every failure mode. Distinguishing "expired"
			// from "wrong signature" from "no such file" hands an anonymous
			// caller an oracle for which keys exist; the specific reason goes
			// to the log, where the operator can see it and the caller cannot.
			slog.Warn("rejected unsigned or invalid file request",
				"path", filePath, "reason", err.Error(), "remote", c.ClientIP())
			c.JSON(http.StatusForbidden, gin.H{
				"errors": []string{"Invalid or expired download URL"},
			})
			return
		}

		// Enforce the mirrored-provider-version approval gate before streaming.
		// Provider files follow the deterministic layout
		// providers/{namespace}/{type}/{version}/{os}/{arch}/{filename}, so a client
		// that can derive that layout for a pending/rejected mirrored version (already
		// hidden from the JSON listing/download endpoints) could otherwise retrieve
		// the raw archive directly through this route, bypassing the approval
		// workflow entirely. Return the same "File not found" response as a
		// genuinely missing file so the gate does not reveal that a hidden version
		// exists.
		//
		// RESOLVED BY NAMESPACE (#972). This lookup used to resolve the default
		// organization first and filter by it, which meant the gate SILENTLY
		// DID NOT RUN for a provider owned by any other organization: the
		// lookup missed, the nested conditions fell through, and the archive
		// was served. An approval gate that skips itself on the deployments it
		// was least tested against is worse than none, because it reports
		// coverage it does not have.
		if providerRepo != nil {
			if ns, pt, ver, _, _, ok := parseProviderFilePath(filePath); ok {
				if provider, _, err := providerRepo.GetProviderByNamespace(c.Request.Context(), ns, pt); err == nil && provider != nil {
					if pv, err := providerRepo.GetVersion(c.Request.Context(), provider.ID, ver); err == nil && pv != nil {
						status, err := providerRepo.GetVersionApprovalStatus(c.Request.Context(), pv.ID)
						if err == nil && status != nil && *status != models.VersionApprovalStatusApproved {
							c.JSON(http.StatusNotFound, gin.H{
								"errors": []string{"File not found"},
							})
							return
						}
					}
				}
			}
		}

		// Check if file exists
		exists, err := storageBackend.Exists(c.Request.Context(), filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []string{"Failed to check file existence"},
			})
			return
		}
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"errors": []string{"File not found"},
			})
			return
		}

		// Get file metadata
		metadata, err := storageBackend.GetMetadata(c.Request.Context(), filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []string{"Failed to get file metadata"},
			})
			return
		}

		// Download file from storage
		reader, err := storageBackend.Download(c.Request.Context(), filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"errors": []string{"Failed to read file"},
			})
			return
		}
		defer reader.Close()

		// Track provider downloads: path is providers/{namespace}/{type}/{version}/{os}/{arch}/{file}
		if providerRepo != nil {
			if ns, pt, ver, osName, arch, ok := parseProviderFilePath(filePath); ok {
				safego.Go(func() { trackProviderDownload(providerRepo, ns, pt, ver, osName, arch) })
				telemetry.ProviderDownloadsTotal.WithLabelValues(ns, pt, osName, arch).Inc()
			}
		}

		// Determine resource type and Content-Type from the path prefix.
		// Provider archives are .zip; module archives are .tar.gz.
		resourceType := "file"
		contentType := "application/gzip"
		if strings.HasPrefix(filePath, "providers/") {
			resourceType = "provider"
			contentType = "application/zip"
		} else if strings.HasPrefix(filePath, "modules/") {
			resourceType = "module"
		}

		// Audit log the file download event asynchronously
		if auditRepo != nil {
			// Route through the same redaction helper AuditMiddleware/LoggerMiddleware
			// use rather than logging the raw path (issue #678 sibling).
			action := "GET " + middleware.RedactSensitivePath(c.Request.URL.Path)
			ip := c.ClientIP()
			safego.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := auditRepo.CreateAuditLog(ctx, &models.AuditLog{
					Action:       action,
					ResourceType: &resourceType,
					IPAddress:    &ip,
				}); err != nil {
					slog.Error("failed to write audit log for file download", "error", err, "action", action)
				}
			})
		}

		// Set response headers
		c.Header("Content-Type", contentType)
		c.Header("Content-Disposition", "attachment")
		c.Header("X-Checksum-SHA256", metadata.Checksum)

		// Stream file to client
		c.DataFromReader(http.StatusOK, metadata.Size, contentType, reader, nil)
	}
}

// downloadTrackTimeout bounds the fire-and-forget download-count updates. The
// response has already been sent, so the only thing at stake is a counter --
// shedding it beats accumulating goroutines against a wedged database.
const downloadTrackTimeout = 5 * time.Second

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
func trackProviderDownload(providerRepo *repositories.ProviderRepository, namespace, providerType, version, osName, arch string) {
	// One budget for the whole operation, matching the audit goroutine 30 lines
	// above (issue #758). This runs fire-and-forget after the response is
	// served and makes FOUR sequential queries; with a bare context.Background()
	// a wedged database left every one of these goroutines resident for the life
	// of the process, one per download.
	//
	// Postgres statement_timeout does not cover this: it bounds a running query,
	// not the wait for a free pooled connection or a blackholed server -- which
	// is precisely when these pile up.
	ctx, cancel := context.WithTimeout(context.Background(), downloadTrackTimeout)
	defer cancel()
	// RESOLVED BY NAMESPACE (#972). Same defect as the approval gate above: a
	// provider owned by any organization other than "default" resolved to
	// nothing here, so its downloads were never counted -- silently, since this
	// runs detached and returns on every miss.
	provider, _, err := providerRepo.GetProviderByNamespace(ctx, namespace, providerType)
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
			if err := providerRepo.IncrementDownloadCount(ctx, p.ID); err != nil {
				// Logged rather than discarded, matching the four sibling call
				// sites. A silently-dropped counter is indistinguishable from
				// a download that never happened.
				slog.Error("failed to increment provider download count",
					"platform_id", p.ID, "error", err)
			}
			return
		}
	}
}
