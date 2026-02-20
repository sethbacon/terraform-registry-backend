// upload.go implements the module archive upload, validation, and registration endpoint for the modules package.
package modules

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/validation"
)

// @Summary      Upload module version
// @Description  Upload a new module version as a .tar.gz archive. Creates the module if it doesn't exist. Requires modules:publish scope.
// @Tags         Modules
// @Security     Bearer
// @Accept       multipart/form-data
// @Produce      json
// @Param        namespace    formData  string  true   "Module namespace"
// @Param        name         formData  string  true   "Module name"
// @Param        system       formData  string  true   "Target system (e.g. aws, azurerm)"
// @Param        version      formData  string  true   "Semantic version (e.g. 1.2.3)"
// @Param        description  formData  string  false  "Module description"
// @Param        source       formData  string  false  "Source URL"
// @Param        file         formData  file    true   "Module archive (.tar.gz, max 100MB)"
// @Success      201  {object}  map[string]interface{}  "id, namespace, name, system, version, checksum, size_bytes"
// @Failure      400  {object}  map[string]interface{}  "Invalid request, bad version format, or invalid archive"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      409  {object}  map[string]interface{}  "Version already exists"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/modules [post]
// UploadHandler handles module upload requests
// Implements: POST /api/v1/modules
// Accepts multipart form with: namespace, name, system, version, description (optional), file
func UploadHandler(db *sql.DB, storageBackend storage.Storage, cfg *config.Config) gin.HandlerFunc {
	moduleRepo := repositories.NewModuleRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	return func(c *gin.Context) {
		// Parse multipart form (max 100MB)
		if err := c.Request.ParseMultipartForm(100 << 20); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to parse multipart form",
			})
			return
		}

		// Get form values
		namespace := c.PostForm("namespace")
		name := c.PostForm("name")
		system := c.PostForm("system")
		version := c.PostForm("version")
		description := c.PostForm("description")
		source := c.PostForm("source")

		// Validate required fields
		if namespace == "" || name == "" || system == "" || version == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Missing required fields: namespace, name, system, version",
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

		// Validate archive format
		if err := validation.ValidateArchive(bytes.NewReader(fileBuffer.Bytes()), validation.MaxArchiveSize); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid archive: %v", err),
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

		// Check if module already exists, create if not
		module, err := moduleRepo.GetModule(c.Request.Context(), org.ID, namespace, name, system)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to query module",
			})
			return
		}

		if module == nil {
			// Create new module
			module = &models.Module{
				OrganizationID: org.ID,
				Namespace:      namespace,
				Name:           name,
				System:         system,
			}
			if description != "" {
				module.Description = &description
			}
			if source != "" {
				module.Source = &source
			}
			// Set created_by for audit tracking
			if userID, exists := c.Get("user_id"); exists {
				if uid, ok := userID.(string); ok {
					module.CreatedBy = &uid
				}
			}

			if err := moduleRepo.CreateModule(c.Request.Context(), module); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to create module: %v", err),
				})
				return
			}
		} else {
			// Update existing module metadata if provided
			if description != "" {
				module.Description = &description
			}
			if source != "" {
				module.Source = &source
			}
			if err := moduleRepo.UpdateModule(c.Request.Context(), module); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to update module",
				})
				return
			}
		}

		// Check for duplicate version
		existingVersion, err := moduleRepo.GetVersion(c.Request.Context(), module.ID, version)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check for existing version",
			})
			return
		}
		if existingVersion != nil {
			c.JSON(http.StatusConflict, gin.H{
				"error": fmt.Sprintf("Version %s already exists for this module", version),
			})
			return
		}

		// Generate storage path: modules/{namespace}/{name}/{system}/{version}.tar.gz
		storagePath := fmt.Sprintf("modules/%s/%s/%s/%s.tar.gz", namespace, name, system, version)

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

		// Extract README from tarball
		readme, err := validation.ExtractReadme(bytes.NewReader(fileBuffer.Bytes()))
		if err != nil {
			// Log warning but don't fail the upload
			fmt.Printf("Warning: Failed to extract README: %v\n", err)
		}

		// Create version record
		moduleVersion := &models.ModuleVersion{
			ModuleID:       module.ID,
			Version:        version,
			StoragePath:    uploadResult.Path,
			StorageBackend: cfg.Storage.DefaultBackend,
			SizeBytes:      uploadResult.Size,
			Checksum:       uploadResult.Checksum,
		}
		// Set published_by for audit tracking
		if userID, exists := c.Get("user_id"); exists {
			if uid, ok := userID.(string); ok {
				moduleVersion.PublishedBy = &uid
			}
		}

		// Set README if extracted
		if readme != "" {
			moduleVersion.Readme = &readme
		}

		if err := moduleRepo.CreateVersion(c.Request.Context(), moduleVersion); err != nil {
			// Try to clean up uploaded file
			_ = storageBackend.Delete(c.Request.Context(), uploadResult.Path)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create version record",
			})
			return
		}

		// Return success response with module metadata
		c.JSON(http.StatusCreated, gin.H{
			"id":         module.ID,
			"namespace":  module.Namespace,
			"name":       module.Name,
			"system":     module.System,
			"version":    moduleVersion.Version,
			"checksum":   moduleVersion.Checksum,
			"size_bytes": moduleVersion.SizeBytes,
			"filename":   header.Filename,
			"created_at": moduleVersion.CreatedAt,
		})
	}
}
