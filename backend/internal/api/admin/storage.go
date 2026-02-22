// storage.go implements handlers for storage backend configuration CRUD operations and connection validation.
package admin

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// StorageHandlers handles storage configuration CRUD operations
type StorageHandlers struct {
	cfg               *config.Config
	storageConfigRepo *repositories.StorageConfigRepository
	tokenCipher       *crypto.TokenCipher
}

// NewStorageHandlers creates a new storage handlers instance
func NewStorageHandlers(cfg *config.Config, storageConfigRepo *repositories.StorageConfigRepository, tokenCipher *crypto.TokenCipher) *StorageHandlers {
	return &StorageHandlers{
		cfg:               cfg,
		storageConfigRepo: storageConfigRepo,
		tokenCipher:       tokenCipher,
	}
}

// GetSetupStatus returns the current setup status (legacy; route now owned by setup.Handlers)
// GET /api/v1/setup/status
func (h *StorageHandlers) GetSetupStatus(c *gin.Context) {
	ctx := c.Request.Context()

	configured, err := h.storageConfigRepo.IsStorageConfigured(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
		return
	}

	settings, err := h.storageConfigRepo.GetSystemSettings(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get system settings"})
		return
	}

	response := gin.H{
		"storage_configured": configured,
		"setup_required":     !configured,
	}

	if settings != nil && settings.StorageConfiguredAt.Valid {
		response["storage_configured_at"] = settings.StorageConfiguredAt.Time
	}

	c.JSON(http.StatusOK, response)
}

// @Summary      Get active storage configuration
// @Description  Returns the currently active storage configuration (credentials redacted). Requires admin scope.
// @Tags         Storage
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  models.StorageConfigResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "No active storage configuration"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/storage/config [get]
// GetActiveStorageConfig returns the currently active storage configuration
// GET /api/v1/storage/config
func (h *StorageHandlers) GetActiveStorageConfig(c *gin.Context) {
	ctx := c.Request.Context()

	storageConfig, err := h.storageConfigRepo.GetActiveStorageConfig(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get storage configuration"})
		return
	}

	if storageConfig == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active storage configuration"})
		return
	}

	c.JSON(http.StatusOK, storageConfig.ToResponse())
}

// @Summary      List storage configurations
// @Description  Returns all storage configurations (credentials redacted). Requires admin scope.
// @Tags         Storage
// @Security     Bearer
// @Produce      json
// @Success      200  {array}   models.StorageConfigResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/storage/configs [get]
// ListStorageConfigs lists all storage configurations
// GET /api/v1/storage/configs
func (h *StorageHandlers) ListStorageConfigs(c *gin.Context) {
	ctx := c.Request.Context()

	configs, err := h.storageConfigRepo.ListStorageConfigs(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list storage configurations"})
		return
	}

	responses := make([]models.StorageConfigResponse, len(configs))
	for i, cfg := range configs {
		responses[i] = cfg.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// @Summary      Get storage configuration
// @Description  Returns a specific storage configuration by ID (credentials redacted). Requires admin scope.
// @Tags         Storage
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Configuration ID (UUID)"
// @Success      200  {object}  models.StorageConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Storage configuration not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/storage/configs/{id} [get]
// GetStorageConfig returns a storage configuration by ID
// GET /api/v1/storage/configs/:id
func (h *StorageHandlers) GetStorageConfig(c *gin.Context) {
	ctx := c.Request.Context()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid configuration ID"})
		return
	}

	storageConfig, err := h.storageConfigRepo.GetStorageConfig(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get storage configuration"})
		return
	}

	if storageConfig == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "storage configuration not found"})
		return
	}

	c.JSON(http.StatusOK, storageConfig.ToResponse())
}

// @Summary      Create storage configuration
// @Description  Create a new storage configuration. Supported backends: local, azure, s3, gcs. Requires admin scope.
// @Tags         Storage
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  models.StorageConfigInput  true  "Storage configuration"
// @Success      201  {object}  models.StorageConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request or validation error"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/storage/configs [post]
// CreateStorageConfig creates a new storage configuration
// POST /api/v1/storage/configs
func (h *StorageHandlers) CreateStorageConfig(c *gin.Context) {
	ctx := c.Request.Context()

	var input models.StorageConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate backend type
	if input.BackendType != "local" && input.BackendType != "azure" && input.BackendType != "s3" && input.BackendType != "gcs" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid backend_type: must be local, azure, s3, or gcs"})
		return
	}

	// Validate required fields based on backend type
	if err := h.validateStorageConfig(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	var userUUID uuid.NullUUID
	if exists {
		if uid, ok := userID.(uuid.UUID); ok {
			userUUID = uuid.NullUUID{UUID: uid, Valid: true}
		}
	}

	// Check if this is the first storage configuration (initial setup)
	configured, err := h.storageConfigRepo.IsStorageConfigured(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
		return
	}

	// Build the storage config model
	storageConfig, err := h.buildStorageConfig(&input, userUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// If storage is already configured, deactivate existing configs first
	if configured {
		if err := h.storageConfigRepo.DeactivateAllStorageConfigs(ctx); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update existing configurations"})
			return
		}
	}

	// Create the new configuration
	if err := h.storageConfigRepo.CreateStorageConfig(ctx, storageConfig); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create storage configuration"})
		return
	}

	// Mark storage as configured if this is the first setup
	if !configured && userUUID.Valid {
		if err := h.storageConfigRepo.SetStorageConfigured(ctx, userUUID.UUID); err != nil {
			// Log but don't fail - config was created
		}
	}

	c.JSON(http.StatusCreated, storageConfig.ToResponse())
}

// @Summary      Update storage configuration
// @Description  Update a storage configuration. Cannot change backend_type of the active configuration. Requires admin scope.
// @Tags         Storage
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                    true  "Configuration ID (UUID)"
// @Param        body  body  models.StorageConfigInput  true  "Storage configuration"
// @Success      200  {object}  models.StorageConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid request or validation error"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Storage configuration not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/storage/configs/{id} [put]
// UpdateStorageConfig updates a storage configuration
// PUT /api/v1/storage/configs/:id
func (h *StorageHandlers) UpdateStorageConfig(c *gin.Context) {
	ctx := c.Request.Context()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid configuration ID"})
		return
	}

	existing, err := h.storageConfigRepo.GetStorageConfig(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get storage configuration"})
		return
	}

	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "storage configuration not found"})
		return
	}

	// Check guard rails - if storage is configured and this is the active config,
	// only allow updates that don't change the backend type
	configured, _ := h.storageConfigRepo.IsStorageConfigured(ctx)
	if configured && existing.IsActive {
		// Allow updates but log a warning
		// In a real implementation, you might want to add more checks here
	}

	var input models.StorageConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate backend type change - not allowed if active
	if configured && existing.IsActive && input.BackendType != existing.BackendType {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "cannot change backend type of active configuration; create a new configuration instead",
		})
		return
	}

	// Validate required fields
	if err := h.validateStorageConfig(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	var userUUID uuid.NullUUID
	if exists {
		if uid, ok := userID.(uuid.UUID); ok {
			userUUID = uuid.NullUUID{UUID: uid, Valid: true}
		}
	}

	// Update the config
	if err := h.updateStorageConfigFromInput(existing, &input, userUUID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := h.storageConfigRepo.UpdateStorageConfig(ctx, existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update storage configuration"})
		return
	}

	c.JSON(http.StatusOK, existing.ToResponse())
}

// @Summary      Delete storage configuration
// @Description  Delete a storage configuration. Cannot delete the active configuration. Requires admin scope.
// @Tags         Storage
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Configuration ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "message: storage configuration deleted"
// @Failure      400  {object}  map[string]interface{}  "Invalid ID or cannot delete active config"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Storage configuration not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/storage/configs/{id} [delete]
// DeleteStorageConfig deletes a storage configuration
// DELETE /api/v1/storage/configs/:id
func (h *StorageHandlers) DeleteStorageConfig(c *gin.Context) {
	ctx := c.Request.Context()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid configuration ID"})
		return
	}

	existing, err := h.storageConfigRepo.GetStorageConfig(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get storage configuration"})
		return
	}

	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "storage configuration not found"})
		return
	}

	// Don't allow deleting the active configuration
	if existing.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete the active storage configuration"})
		return
	}

	if err := h.storageConfigRepo.DeleteStorageConfig(ctx, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete storage configuration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "storage configuration deleted"})
}

// @Summary      Activate storage configuration
// @Description  Set a storage configuration as the active one. All other configurations will be deactivated. Requires admin scope.
// @Tags         Storage
// @Security     Bearer
// @Produce      json
// @Param        id  path  string  true  "Configuration ID (UUID)"
// @Success      200  {object}  map[string]interface{}  "message: string, config: models.StorageConfigResponse"
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration ID"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Storage configuration not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/storage/configs/{id}/activate [post]
// ActivateStorageConfig activates a storage configuration
// POST /api/v1/storage/configs/:id/activate
func (h *StorageHandlers) ActivateStorageConfig(c *gin.Context) {
	ctx := c.Request.Context()

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid configuration ID"})
		return
	}

	existing, err := h.storageConfigRepo.GetStorageConfig(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get storage configuration"})
		return
	}

	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "storage configuration not found"})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	var userUUID uuid.UUID
	if exists {
		if uid, ok := userID.(uuid.UUID); ok {
			userUUID = uid
		}
	}

	if err := h.storageConfigRepo.ActivateStorageConfig(ctx, id, userUUID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to activate storage configuration"})
		return
	}

	// Refresh the config
	existing, _ = h.storageConfigRepo.GetStorageConfig(ctx, id)

	c.JSON(http.StatusOK, gin.H{
		"message": "storage configuration activated",
		"config":  existing.ToResponse(),
	})
}

// @Summary      Test storage configuration
// @Description  Validates a storage configuration and performs a live connectivity probe against the target backend
// @Description  without saving anything to the database. The backend is instantiated from the provided input, then
// @Description  an Exists probe (10-second timeout) is executed to confirm reachability and correct credentials.
// @Description  Supported backends: local, azure, s3, gcs. Requires admin scope.
// @Tags         Storage
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  models.StorageConfigInput  true  "Storage configuration to test"
// @Success      200  {object}  map[string]interface{}  "success: bool, message: string — true when the backend is reachable"
// @Failure      400  {object}  map[string]interface{}  "Invalid or incomplete configuration input"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/storage/configs/test [post]
// TestStorageConfig tests a storage configuration without saving
// POST /api/v1/storage/configs/test
func (h *StorageHandlers) TestStorageConfig(c *gin.Context) {
	var input models.StorageConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate required fields
	if err := h.validateStorageConfig(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build a temporary config from the input to test the connection
	testCfg := &config.Config{}
	testCfg.Storage.DefaultBackend = input.BackendType
	switch input.BackendType {
	case "local":
		testCfg.Storage.Local = config.LocalStorageConfig{
			BasePath:      input.LocalBasePath,
			ServeDirectly: false,
		}
	case "azure":
		testCfg.Storage.Azure = config.AzureStorageConfig{
			AccountName:   input.AzureAccountName,
			AccountKey:    input.AzureAccountKey,
			ContainerName: input.AzureContainerName,
			CDNURL:        input.AzureCDNURL,
		}
	case "s3":
		testCfg.Storage.S3 = config.S3StorageConfig{
			Endpoint:             input.S3Endpoint,
			Region:               input.S3Region,
			Bucket:               input.S3Bucket,
			AuthMethod:           input.S3AuthMethod,
			AccessKeyID:          input.S3AccessKeyID,
			SecretAccessKey:      input.S3SecretAccessKey,
			RoleARN:              input.S3RoleARN,
			RoleSessionName:      input.S3RoleSessionName,
			ExternalID:           input.S3ExternalID,
			WebIdentityTokenFile: input.S3WebIdentityTokenFile,
		}
	case "gcs":
		testCfg.Storage.GCS = config.GCSStorageConfig{
			Bucket:          input.GCSBucket,
			ProjectID:       input.GCSProjectID,
			AuthMethod:      input.GCSAuthMethod,
			CredentialsFile: input.GCSCredentialsFile,
			CredentialsJSON: input.GCSCredentialsJSON,
			Endpoint:        input.GCSEndpoint,
		}
	}

	// Instantiate the backend
	backend, err := storage.NewStorage(testCfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "failed to initialise storage backend: " + err.Error(),
		})
		return
	}

	// Probe the backend with a lightweight Exists call
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	_, probeErr := backend.Exists(ctx, ".connectivity-test")
	if probeErr != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "storage backend unreachable: " + probeErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "storage connection successful",
	})
}

// Helper functions

func (h *StorageHandlers) validateStorageConfig(input *models.StorageConfigInput) error {
	switch input.BackendType {
	case "local":
		if input.LocalBasePath == "" {
			return &ValidationError{Field: "local_base_path", Message: "required for local storage"}
		}
	case "azure":
		if input.AzureAccountName == "" {
			return &ValidationError{Field: "azure_account_name", Message: "required for Azure storage"}
		}
		if input.AzureContainerName == "" {
			return &ValidationError{Field: "azure_container_name", Message: "required for Azure storage"}
		}
		if input.AzureAccountKey == "" {
			return &ValidationError{Field: "azure_account_key", Message: "required for Azure storage"}
		}
	case "s3":
		if input.S3Bucket == "" {
			return &ValidationError{Field: "s3_bucket", Message: "required for S3 storage"}
		}
		if input.S3Region == "" {
			return &ValidationError{Field: "s3_region", Message: "required for S3 storage"}
		}
		// Validate auth method specific requirements
		if input.S3AuthMethod == "static" {
			if input.S3AccessKeyID == "" || input.S3SecretAccessKey == "" {
				return &ValidationError{Field: "s3_access_key_id", Message: "required for static auth"}
			}
		}
		if input.S3AuthMethod == "assume_role" || input.S3AuthMethod == "oidc" {
			if input.S3RoleARN == "" {
				return &ValidationError{Field: "s3_role_arn", Message: "required for assume_role/oidc auth"}
			}
		}
	case "gcs":
		if input.GCSBucket == "" {
			return &ValidationError{Field: "gcs_bucket", Message: "required for GCS storage"}
		}
		// For service_account auth, require credentials
		if input.GCSAuthMethod == "service_account" {
			if input.GCSCredentialsFile == "" && input.GCSCredentialsJSON == "" {
				return &ValidationError{Field: "gcs_credentials", Message: "credentials_file or credentials_json required for service_account auth"}
			}
		}
	}
	return nil
}

func (h *StorageHandlers) buildStorageConfig(input *models.StorageConfigInput, userID uuid.NullUUID) (*models.StorageConfig, error) {
	now := time.Now()
	config := &models.StorageConfig{
		ID:          uuid.New(),
		BackendType: input.BackendType,
		IsActive:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   userID,
		UpdatedBy:   userID,
	}

	// Set backend-specific fields
	switch input.BackendType {
	case "local":
		config.LocalBasePath = sql.NullString{String: input.LocalBasePath, Valid: input.LocalBasePath != ""}
		if input.LocalServeDirectly != nil {
			config.LocalServeDirectly = sql.NullBool{Bool: *input.LocalServeDirectly, Valid: true}
		} else {
			config.LocalServeDirectly = sql.NullBool{Bool: true, Valid: true}
		}

	case "azure":
		config.AzureAccountName = sql.NullString{String: input.AzureAccountName, Valid: input.AzureAccountName != ""}
		config.AzureContainerName = sql.NullString{String: input.AzureContainerName, Valid: input.AzureContainerName != ""}
		config.AzureCDNURL = sql.NullString{String: input.AzureCDNURL, Valid: input.AzureCDNURL != ""}
		if input.AzureAccountKey != "" {
			encrypted, err := h.tokenCipher.Seal(input.AzureAccountKey)
			if err != nil {
				return nil, err
			}
			config.AzureAccountKeyEncrypted = sql.NullString{String: encrypted, Valid: true}
		}

	case "s3":
		config.S3Endpoint = sql.NullString{String: input.S3Endpoint, Valid: input.S3Endpoint != ""}
		config.S3Region = sql.NullString{String: input.S3Region, Valid: input.S3Region != ""}
		config.S3Bucket = sql.NullString{String: input.S3Bucket, Valid: input.S3Bucket != ""}
		config.S3AuthMethod = sql.NullString{String: input.S3AuthMethod, Valid: input.S3AuthMethod != ""}
		config.S3RoleARN = sql.NullString{String: input.S3RoleARN, Valid: input.S3RoleARN != ""}
		config.S3RoleSessionName = sql.NullString{String: input.S3RoleSessionName, Valid: input.S3RoleSessionName != ""}
		config.S3ExternalID = sql.NullString{String: input.S3ExternalID, Valid: input.S3ExternalID != ""}
		config.S3WebIdentityTokenFile = sql.NullString{String: input.S3WebIdentityTokenFile, Valid: input.S3WebIdentityTokenFile != ""}
		if input.S3AccessKeyID != "" {
			encrypted, err := h.tokenCipher.Seal(input.S3AccessKeyID)
			if err != nil {
				return nil, err
			}
			config.S3AccessKeyIDEncrypted = sql.NullString{String: encrypted, Valid: true}
		}
		if input.S3SecretAccessKey != "" {
			encrypted, err := h.tokenCipher.Seal(input.S3SecretAccessKey)
			if err != nil {
				return nil, err
			}
			config.S3SecretAccessKeyEncrypted = sql.NullString{String: encrypted, Valid: true}
		}

	case "gcs":
		config.GCSBucket = sql.NullString{String: input.GCSBucket, Valid: input.GCSBucket != ""}
		config.GCSProjectID = sql.NullString{String: input.GCSProjectID, Valid: input.GCSProjectID != ""}
		config.GCSAuthMethod = sql.NullString{String: input.GCSAuthMethod, Valid: input.GCSAuthMethod != ""}
		config.GCSCredentialsFile = sql.NullString{String: input.GCSCredentialsFile, Valid: input.GCSCredentialsFile != ""}
		config.GCSEndpoint = sql.NullString{String: input.GCSEndpoint, Valid: input.GCSEndpoint != ""}
		if input.GCSCredentialsJSON != "" {
			encrypted, err := h.tokenCipher.Seal(input.GCSCredentialsJSON)
			if err != nil {
				return nil, err
			}
			config.GCSCredentialsJSONEncrypted = sql.NullString{String: encrypted, Valid: true}
		}
	}

	return config, nil
}

func (h *StorageHandlers) updateStorageConfigFromInput(config *models.StorageConfig, input *models.StorageConfigInput, userID uuid.NullUUID) error {
	config.BackendType = input.BackendType
	config.UpdatedBy = userID

	// Update backend-specific fields
	switch input.BackendType {
	case "local":
		config.LocalBasePath = sql.NullString{String: input.LocalBasePath, Valid: input.LocalBasePath != ""}
		if input.LocalServeDirectly != nil {
			config.LocalServeDirectly = sql.NullBool{Bool: *input.LocalServeDirectly, Valid: true}
		}

	case "azure":
		config.AzureAccountName = sql.NullString{String: input.AzureAccountName, Valid: input.AzureAccountName != ""}
		config.AzureContainerName = sql.NullString{String: input.AzureContainerName, Valid: input.AzureContainerName != ""}
		config.AzureCDNURL = sql.NullString{String: input.AzureCDNURL, Valid: input.AzureCDNURL != ""}
		if input.AzureAccountKey != "" {
			encrypted, err := h.tokenCipher.Seal(input.AzureAccountKey)
			if err != nil {
				return err
			}
			config.AzureAccountKeyEncrypted = sql.NullString{String: encrypted, Valid: true}
		}

	case "s3":
		config.S3Endpoint = sql.NullString{String: input.S3Endpoint, Valid: input.S3Endpoint != ""}
		config.S3Region = sql.NullString{String: input.S3Region, Valid: input.S3Region != ""}
		config.S3Bucket = sql.NullString{String: input.S3Bucket, Valid: input.S3Bucket != ""}
		config.S3AuthMethod = sql.NullString{String: input.S3AuthMethod, Valid: input.S3AuthMethod != ""}
		config.S3RoleARN = sql.NullString{String: input.S3RoleARN, Valid: input.S3RoleARN != ""}
		config.S3RoleSessionName = sql.NullString{String: input.S3RoleSessionName, Valid: input.S3RoleSessionName != ""}
		config.S3ExternalID = sql.NullString{String: input.S3ExternalID, Valid: input.S3ExternalID != ""}
		config.S3WebIdentityTokenFile = sql.NullString{String: input.S3WebIdentityTokenFile, Valid: input.S3WebIdentityTokenFile != ""}
		if input.S3AccessKeyID != "" {
			encrypted, err := h.tokenCipher.Seal(input.S3AccessKeyID)
			if err != nil {
				return err
			}
			config.S3AccessKeyIDEncrypted = sql.NullString{String: encrypted, Valid: true}
		}
		if input.S3SecretAccessKey != "" {
			encrypted, err := h.tokenCipher.Seal(input.S3SecretAccessKey)
			if err != nil {
				return err
			}
			config.S3SecretAccessKeyEncrypted = sql.NullString{String: encrypted, Valid: true}
		}

	case "gcs":
		config.GCSBucket = sql.NullString{String: input.GCSBucket, Valid: input.GCSBucket != ""}
		config.GCSProjectID = sql.NullString{String: input.GCSProjectID, Valid: input.GCSProjectID != ""}
		config.GCSAuthMethod = sql.NullString{String: input.GCSAuthMethod, Valid: input.GCSAuthMethod != ""}
		config.GCSCredentialsFile = sql.NullString{String: input.GCSCredentialsFile, Valid: input.GCSCredentialsFile != ""}
		config.GCSEndpoint = sql.NullString{String: input.GCSEndpoint, Valid: input.GCSEndpoint != ""}
		if input.GCSCredentialsJSON != "" {
			encrypted, err := h.tokenCipher.Seal(input.GCSCredentialsJSON)
			if err != nil {
				return err
			}
			config.GCSCredentialsJSONEncrypted = sql.NullString{String: encrypted, Valid: true}
		}
	}

	return nil
}

// ValidationError represents a validation error for a specific field
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Message
}
