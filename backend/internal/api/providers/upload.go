// upload.go implements the provider binary upload, checksum validation, and platform registration endpoint for the providers package.
package providers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/validation"
	"github.com/terraform-registry/terraform-registry/pkg/checksum"
)

const (
	// MaxProviderBinarySize is the maximum size for a provider binary (500MB)
	MaxProviderBinarySize = 500 << 20 // 500MB
)

// @Summary      Upload provider platform binary
// @Description  Upload a provider binary (.zip) for a specific platform. Creates provider and version if they don't exist. Requires providers:publish scope.
// @Tags         Providers
// @Security     Bearer
// @Accept       multipart/form-data
// @Produce      json
// @Param        namespace      formData  string  true   "Provider namespace"
// @Param        type           formData  string  true   "Provider type (e.g. aws, azurerm)"
// @Param        version        formData  string  true   "Semantic version (e.g. 1.2.3)"
// @Param        os             formData  string  true   "Target OS (e.g. linux, darwin, windows)"
// @Param        arch           formData  string  true   "Target architecture (e.g. amd64, arm64)"
// @Param        protocols      formData  string  false  "JSON array of supported protocols (default [\"5.0\"])"
// @Param        gpg_public_key formData  string  false  "ASCII-armored GPG public key for signing verification"
// @Param        description    formData  string  false  "Provider description"
// @Param        source         formData  string  false  "Source URL"
// @Param        file           formData  file    true   "Provider binary (.zip, max 500MB)"
// @Success      201  {object}  map[string]interface{}  "id, namespace, type, version, os, arch, checksum, size_bytes"
// @Failure      400  {object}  map[string]interface{}  "Invalid request, version format, platform, or binary"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "Platform already exists for this version"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/providers [post]
// UploadHandler handles provider upload requests
// Implements: POST /api/v1/providers
// Accepts multipart form with: namespace, type, version, os, arch, protocols, gpg_public_key, file
func UploadHandler(db *sql.DB, storageBackend storage.Storage, cfg *config.Config) gin.HandlerFunc {
	providerRepo := repositories.NewProviderRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	return func(c *gin.Context) {
		// Parse multipart form (max 500MB for provider binaries)
		if err := c.Request.ParseMultipartForm(MaxProviderBinarySize); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to parse multipart form",
			})
			return
		}

		// Get form values
		namespace := c.PostForm("namespace")
		providerType := c.PostForm("type")
		version := c.PostForm("version")
		os := c.PostForm("os")
		arch := c.PostForm("arch")
		protocolsStr := c.PostForm("protocols")
		gpgPublicKey := c.PostForm("gpg_public_key")
		description := c.PostForm("description")
		source := c.PostForm("source")

		// Validate required fields
		if namespace == "" || providerType == "" || version == "" || os == "" || arch == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Missing required fields: namespace, type, version, os, arch",
			})
			return
		}

		// Validate semantic versioning
		if err := validation.ValidateSemver(version); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid version format: %v", err),
			})
			return
		}

		// Validate platform (OS/arch combination)
		if err := validation.ValidatePlatform(os, arch); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid platform: %v", err),
			})
			return
		}

		// Parse protocols JSON array
		var protocols []string
		if protocolsStr != "" {
			if err := json.Unmarshal([]byte(protocolsStr), &protocols); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": fmt.Sprintf("Invalid protocols format (must be JSON array): %v", err),
				})
				return
			}
		} else {
			// Default to protocol 5.0 if not specified
			protocols = []string{"5.0"}
		}

		// Validate GPG public key format if provided
		if gpgPublicKey != "" {
			if err := validation.ParseGPGPublicKey(gpgPublicKey); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": fmt.Sprintf("Invalid GPG public key: %v", err),
				})
				return
			}
			// Normalize the key
			gpgPublicKey = validation.NormalizeGPGKey(gpgPublicKey)
		}

		// Get uploaded file
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Missing or invalid file upload",
			})
			return
		}
		defer file.Close()

		// Read file into buffer for validation and upload
		fileBuffer := &bytes.Buffer{}
		size, err := io.Copy(fileBuffer, file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to read uploaded file",
			})
			return
		}

		// Validate provider binary (ZIP format and size)
		if err := validation.ValidateProviderBinary(fileBuffer.Bytes(), MaxProviderBinarySize); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid provider binary: %v", err),
			})
			return
		}

		// Calculate SHA256 checksum
		sha256sum, err := checksum.CalculateSHA256(bytes.NewReader(fileBuffer.Bytes()))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to calculate checksum",
			})
			return
		}

		// Get organization context
		org, err := orgRepo.GetDefaultOrganization(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get organization context",
			})
			return
		}
		if org == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Default organization not found",
			})
			return
		}

		// Check if provider already exists, create if not
		provider, err := providerRepo.GetProvider(c.Request.Context(), org.ID, namespace, providerType)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to query provider",
			})
			return
		}

		if provider == nil {
			// Create new provider
			provider = &models.Provider{
				OrganizationID: org.ID,
				Namespace:      namespace,
				Type:           providerType,
			}
			if description != "" {
				provider.Description = &description
			}
			if source != "" {
				provider.Source = &source
			}
			// Set created_by for audit tracking
			if userID, exists := c.Get("user_id"); exists {
				if uid, ok := userID.(string); ok {
					provider.CreatedBy = &uid
				}
			}

			if err := providerRepo.CreateProvider(c.Request.Context(), provider); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to create provider: %v", err),
				})
				return
			}
		} else {
			// Update existing provider metadata if provided
			if description != "" {
				provider.Description = &description
			}
			if source != "" {
				provider.Source = &source
			}
			if err := providerRepo.UpdateProvider(c.Request.Context(), provider); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to update provider",
				})
				return
			}
		}

		// Check if version already exists, create if not
		providerVersion, err := providerRepo.GetVersion(c.Request.Context(), provider.ID, version)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to query provider version",
			})
			return
		}

		if providerVersion == nil {
			// Create new version
			// Note: shasums_url and shasums_signature_url would be set separately
			// For now, we'll leave them empty as they're typically external URLs
			providerVersion = &models.ProviderVersion{
				ProviderID:         provider.ID,
				Version:            version,
				Protocols:          protocols,
				GPGPublicKey:       gpgPublicKey,
				ShasumURL:          "",
				ShasumSignatureURL: "",
			}
			// Set published_by for audit tracking
			if userID, exists := c.Get("user_id"); exists {
				if uid, ok := userID.(string); ok {
					providerVersion.PublishedBy = &uid
				}
			}

			if err := providerRepo.CreateVersion(c.Request.Context(), providerVersion); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to create provider version: %v", err),
				})
				return
			}
		}

		// Check for duplicate platform
		existingPlatform, err := providerRepo.GetPlatform(c.Request.Context(), providerVersion.ID, os, arch)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check for existing platform",
			})
			return
		}
		if existingPlatform != nil {
			c.JSON(http.StatusConflict, gin.H{
				"error": fmt.Sprintf("Platform %s/%s already exists for version %s", os, arch, version),
			})
			return
		}

		// Generate storage path: providers/{namespace}/{type}/{version}/{os}_{arch}.zip
		storagePath := fmt.Sprintf("providers/%s/%s/%s/%s_%s.zip", namespace, providerType, version, os, arch)

		// Upload to storage backend
		uploadResult, err := storageBackend.Upload(
			c.Request.Context(),
			storagePath,
			bytes.NewReader(fileBuffer.Bytes()),
			size,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to upload file: %v", err),
			})
			return
		}

		// Create platform record
		platform := &models.ProviderPlatform{
			ProviderVersionID: providerVersion.ID,
			OS:                os,
			Arch:              arch,
			Filename:          header.Filename,
			StoragePath:       uploadResult.Path,
			StorageBackend:    cfg.Storage.DefaultBackend,
			SizeBytes:         uploadResult.Size,
			Shasum:            sha256sum,
		}

		if err := providerRepo.CreatePlatform(c.Request.Context(), platform); err != nil {
			// Try to clean up uploaded file
			_ = storageBackend.Delete(c.Request.Context(), uploadResult.Path)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create platform record",
			})
			return
		}

		// Return success response with provider metadata
		c.JSON(http.StatusCreated, gin.H{
			"id":         provider.ID,
			"namespace":  provider.Namespace,
			"type":       provider.Type,
			"version":    providerVersion.Version,
			"os":         platform.OS,
			"arch":       platform.Arch,
			"protocols":  providerVersion.Protocols,
			"checksum":   platform.Shasum,
			"size_bytes": platform.SizeBytes,
			"filename":   header.Filename,
		})
	}
}
