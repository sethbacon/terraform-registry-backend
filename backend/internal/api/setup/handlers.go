// Package setup implements HTTP handlers for the first-run setup wizard.
// These endpoints are authenticated via setup token (not JWT/API key) and are
// permanently disabled after setup completes. They allow configuring OIDC,
// storage, and the initial admin user through the frontend wizard or via curl.
package setup

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	ldappkg "github.com/terraform-registry/terraform-registry/internal/auth/ldap"
	"github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scanner"
	"github.com/terraform-registry/terraform-registry/internal/scanner/installer"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// Handlers holds all dependencies for setup wizard endpoints.
type Handlers struct {
	cfg               *config.Config
	tokenCipher       *crypto.TokenCipher
	oidcConfigRepo    *repositories.OIDCConfigRepository
	storageConfigRepo *repositories.StorageConfigRepository
	userRepo          *repositories.UserRepository
	orgRepo           *repositories.OrganizationRepository
	authHandlers      *admin.AuthHandlers // to swap OIDC provider at runtime
	installFunc       installer.InstallFunc
}

// NewHandlers creates a new setup Handlers instance.
func NewHandlers(
	cfg *config.Config,
	tokenCipher *crypto.TokenCipher,
	oidcConfigRepo *repositories.OIDCConfigRepository,
	storageConfigRepo *repositories.StorageConfigRepository,
	userRepo *repositories.UserRepository,
	orgRepo *repositories.OrganizationRepository,
	authHandlers *admin.AuthHandlers,
) *Handlers {
	return &Handlers{
		cfg:               cfg,
		tokenCipher:       tokenCipher,
		oidcConfigRepo:    oidcConfigRepo,
		storageConfigRepo: storageConfigRepo,
		userRepo:          userRepo,
		orgRepo:           orgRepo,
		authHandlers:      authHandlers,
	}
}

// @Summary      Get enhanced setup status
// @Description  Returns the full setup status including authentication (OIDC/LDAP), storage, scanning, and admin configuration state. No authentication required.
// @Tags         Setup
// @Produce      json
// @Success      200  {object}  models.SetupStatus
// @Failure      500  {object}  map[string]interface{}
// @Router       /api/v1/setup/status [get]
func (h *Handlers) GetSetupStatus(c *gin.Context) {
	ctx := c.Request.Context()

	status, err := h.oidcConfigRepo.GetEnhancedSetupStatus(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get setup status"})
		return
	}

	scanningConfigured, _ := h.oidcConfigRepo.GetScanningConfigured(ctx)

	response := gin.H{
		"setup_completed":       status.SetupCompleted,
		"storage_configured":    status.StorageConfigured,
		"oidc_configured":       status.OIDCConfigured,
		"ldap_configured":       status.LDAPConfigured,
		"auth_method":           status.AuthMethod,
		"admin_configured":      status.AdminConfigured,
		"setup_required":        status.SetupRequired,
		"scanning_configured":   scanningConfigured,
		"pending_feature_setup": status.PendingFeatureSetup,
	}

	if status.StorageConfiguredAt != nil {
		response["storage_configured_at"] = status.StorageConfiguredAt
	}

	c.JSON(http.StatusOK, response)
}

// @Summary      Validate setup token
// @Description  Validates the provided setup token. Returns 200 if valid. Used by the frontend wizard to verify the token before proceeding.
// @Tags         Setup
// @Security     SetupToken
// @Produce      json
// @Success      200  {object}  setup.ValidateTokenResponse
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Router       /api/v1/setup/validate-token [post]
func (h *Handlers) ValidateToken(c *gin.Context) {
	// If we reach this handler, the SetupTokenMiddleware has already validated the token
	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"message": "Setup token is valid. You may proceed with setup.",
	})
}

// @Summary      Test OIDC configuration
// @Description  Tests an OIDC provider configuration by performing discovery and verifying the issuer endpoint responds. Does NOT save anything.
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body  models.OIDCConfigInput  true  "OIDC configuration to test"
// @Success      200  {object}  setup.TestOIDCConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Router       /api/v1/setup/oidc/test [post]
func (h *Handlers) TestOIDCConfig(c *gin.Context) {
	var input models.OIDCConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateOIDCInput(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build a temporary OIDCConfig to test discovery
	scopes := input.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	testCfg := &config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    input.IssuerURL,
		ClientID:     input.ClientID,
		ClientSecret: input.ClientSecret,
		RedirectURL:  input.RedirectURL,
		Scopes:       scopes,
	}

	// Attempt OIDC discovery — this calls the .well-known endpoint
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	provider, err := oidc.NewOIDCProviderWithContext(ctx, testCfg)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": fmt.Sprintf("OIDC discovery failed: %v", err),
		})
		return
	}

	_ = provider // Discovery succeeded

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "OIDC provider discovery succeeded. The provider is reachable and correctly configured.",
		"issuer":  input.IssuerURL,
	})
}

// @Summary      Save OIDC configuration
// @Description  Saves OIDC provider configuration to the database (encrypted) and activates it for runtime use.
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body  models.OIDCConfigInput  true  "OIDC configuration to save"
// @Success      200  {object}  models.OIDCConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/setup/oidc [post]
func (h *Handlers) SaveOIDCConfig(c *gin.Context) {
	var input models.OIDCConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateOIDCInput(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Encrypt the client secret
	encryptedSecret, err := h.tokenCipher.Seal(input.ClientSecret)
	if err != nil {
		slog.Error("setup: failed to encrypt OIDC client secret", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt client secret"})
		return
	}

	// Build scopes JSON
	scopes := input.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	scopesJSON, _ := json.Marshal(scopes) // nolint:errcheck

	// Build extra config JSON
	var extraConfigJSON []byte
	if input.ExtraConfig != nil {
		extraConfigJSON, _ = json.Marshal(input.ExtraConfig) // nolint:errcheck
	} else {
		extraConfigJSON = []byte("{}")
	}

	// Build name
	name := input.Name
	if name == "" {
		name = "default"
	}

	// Deactivate any existing OIDC configs
	if err := h.oidcConfigRepo.DeactivateAllOIDCConfigs(ctx); err != nil {
		slog.Error("setup: failed to deactivate existing OIDC configs", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare OIDC configuration"})
		return
	}

	// Create the new OIDC config
	now := time.Now()
	oidcCfg := &models.OIDCConfig{
		ID:                    uuid.New(),
		Name:                  name,
		ProviderType:          input.ProviderType,
		IssuerURL:             input.IssuerURL,
		ClientID:              input.ClientID,
		ClientSecretEncrypted: encryptedSecret,
		RedirectURL:           input.RedirectURL,
		Scopes:                scopesJSON,
		IsActive:              true,
		ExtraConfig:           extraConfigJSON,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if err := h.oidcConfigRepo.CreateOIDCConfig(ctx, oidcCfg); err != nil {
		slog.Error("setup: failed to create OIDC config", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save OIDC configuration"})
		return
	}

	// Mark OIDC as configured
	if err := h.oidcConfigRepo.SetOIDCConfigured(ctx); err != nil {
		slog.Error("setup: failed to mark OIDC as configured", "error", err)
		// Non-fatal — config was saved
	}

	// Instantiate and swap the live OIDC provider so logins work immediately
	liveCfg := &config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    input.IssuerURL,
		ClientID:     input.ClientID,
		ClientSecret: input.ClientSecret,
		RedirectURL:  input.RedirectURL,
		Scopes:       scopes,
	}

	liveProvider, err := oidc.NewOIDCProvider(liveCfg)
	if err != nil {
		slog.Warn("setup: OIDC config saved but live provider initialization failed",
			"error", err, "issuer", input.IssuerURL)
		// Non-fatal — config is saved, provider can be loaded on next restart
	} else {
		h.authHandlers.SetOIDCProvider(liveProvider)
		slog.Info("setup: OIDC provider activated", "issuer", input.IssuerURL)
	}

	c.JSON(http.StatusOK, oidcCfg.ToResponse())
}

// @Summary      Test storage configuration
// @Description  Tests a storage backend configuration without saving. Performs a live connectivity probe.
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body  models.StorageConfigInput  true  "Storage configuration to test"
// @Success      200  {object}  setup.TestStorageConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Router       /api/v1/setup/storage/test [post]
func (h *Handlers) TestStorageConfig(c *gin.Context) {
	var input models.StorageConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build a temporary config from input
	testCfg := buildTestStorageConfig(&input)

	// Instantiate the backend
	backend, err := storage.NewStorage(testCfg)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Failed to initialize storage backend: " + err.Error(),
		})
		return
	}

	// Probe with a 10-second timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	_, probeErr := backend.Exists(ctx, ".connectivity-test")
	if probeErr != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Storage connectivity test failed: " + probeErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Storage backend is reachable and correctly configured.",
	})
}

// @Summary      Save storage configuration
// @Description  Saves storage backend configuration to the database and marks storage as configured.
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body  models.StorageConfigInput  true  "Storage configuration to save"
// @Success      200  {object}  setup.SaveStorageConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/setup/storage [post]
func (h *Handlers) SaveStorageConfig(c *gin.Context) {
	var input models.StorageConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Encrypt sensitive fields
	storageCfg, err := h.buildEncryptedStorageConfig(&input)
	if err != nil {
		slog.Error("setup: failed to encrypt storage credentials", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt storage credentials"})
		return
	}

	// Deactivate existing configs
	if err := h.storageConfigRepo.DeactivateAllStorageConfigs(ctx); err != nil {
		slog.Error("setup: failed to deactivate existing storage configs", "error", err)
	}

	// Create the new storage config
	if err := h.storageConfigRepo.CreateStorageConfig(ctx, storageCfg); err != nil {
		slog.Error("setup: failed to create storage config", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save storage configuration"})
		return
	}

	// Mark storage as configured (use null UUID since no user exists yet during setup)
	if err := h.storageConfigRepo.SetStorageConfigured(ctx, uuid.Nil); err != nil {
		slog.Error("setup: failed to mark storage as configured", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Storage configuration saved successfully",
		"config":  storageCfg.ToResponse(),
	})
}

// ConfigureAdminInput is the request body for the admin setup endpoint
type ConfigureAdminInput struct {
	Email string `json:"email" binding:"required,email"`
}

// @Summary      Configure initial admin user
// @Description  Creates the initial admin user record and adds them to the default organization with admin role. The email must match the OIDC identity that will be used for the first login.
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body  ConfigureAdminInput  true  "Admin user email"
// @Success      200  {object}  setup.ConfigureAdminResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid email"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/setup/admin [post]
func (h *Handlers) ConfigureAdmin(c *gin.Context) {
	var input ConfigureAdminInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "A valid email address is required"})
		return
	}

	ctx := c.Request.Context()
	email := strings.TrimSpace(strings.ToLower(input.Email))

	// Get the default organization
	defaultOrg, err := h.orgRepo.GetDefaultOrganization(ctx)
	if err != nil || defaultOrg == nil {
		slog.Error("setup: failed to get default organization", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to find default organization"})
		return
	}

	// Create the user record (without OIDC sub — will be linked on first login)
	user := &models.User{
		Email: email,
		Name:  email, // Will be updated from OIDC claims on first login
	}

	if err := h.userRepo.CreateUser(ctx, user); err != nil {
		// User might already exist — try to find them
		existingUser, findErr := h.userRepo.GetUserByEmail(ctx, email)
		if findErr != nil || existingUser == nil {
			slog.Error("setup: failed to create admin user", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create admin user"})
			return
		}
		user = existingUser
	}

	// Add user to default organization with admin role template
	if err := h.orgRepo.AddMemberWithParams(ctx, defaultOrg.ID, user.ID, "admin"); err != nil {
		// Might already be a member — try to update their role
		if updateErr := h.orgRepo.UpdateMemberRole(ctx, defaultOrg.ID, user.ID, "admin"); updateErr != nil {
			slog.Error("setup: failed to add admin to organization", "error", err, "update_error", updateErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add admin user to organization"})
			return
		}
	}

	// Store the pending admin email for email-matching during first OIDC login
	if err := h.oidcConfigRepo.SetPendingAdminEmail(ctx, email); err != nil {
		slog.Error("setup: failed to set pending admin email", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Admin user configured successfully",
		"email":        email,
		"organization": defaultOrg.DisplayName,
		"role":         "Administrator",
	})
}

// @Summary      Complete setup
// @Description  Finalizes the initial setup. Verifies that authentication (OIDC or LDAP), storage, and admin user are configured, then permanently disables setup endpoints by clearing the setup token.
// @Tags         Setup
// @Security     SetupToken
// @Produce      json
// @Success      200  {object}  setup.CompleteSetupResponse
// @Failure      400  {object}  map[string]interface{}  "Setup is incomplete — missing required configuration"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/setup/complete [post]
func (h *Handlers) CompleteSetup(c *gin.Context) {
	ctx := c.Request.Context()

	// Verify all required components are configured
	status, err := h.oidcConfigRepo.GetEnhancedSetupStatus(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
		return
	}

	scanningConfigured, _ := h.oidcConfigRepo.GetScanningConfigured(ctx)

	// If this is a pending-feature completion (initial setup was already done),
	// only verify the pending features are now configured.
	if status.PendingFeatureSetup {
		if !scanningConfigured {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Feature setup is incomplete. The following components must be configured: security scanning",
				"missing": []string{"security scanning"},
			})
			return
		}

		// Clear the setup token hash to re-disable setup endpoints
		if err := h.oidcConfigRepo.SetSetupCompleted(ctx); err != nil {
			slog.Error("setup: failed to complete feature setup", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete feature setup"})
			return
		}

		slog.Info("setup: pending feature setup completed successfully")
		c.JSON(http.StatusOK, gin.H{
			"message":         "Feature setup completed successfully.",
			"setup_completed": true,
		})
		return
	}

	missing := make([]string, 0)
	// Auth is configured if either OIDC or LDAP is set up
	if !status.OIDCConfigured && !status.LDAPConfigured {
		missing = append(missing, "authentication (OIDC or LDAP)")
	}
	if !status.StorageConfigured {
		missing = append(missing, "storage backend")
	}
	if !status.AdminConfigured {
		missing = append(missing, "admin user")
	}

	if len(missing) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Setup is incomplete. The following components must be configured: " + strings.Join(missing, ", "),
			"missing": missing,
		})
		return
	}

	// Mark setup as completed — this also NULLs the setup_token_hash,
	// permanently disabling all setup endpoints.
	if err := h.oidcConfigRepo.SetSetupCompleted(ctx); err != nil {
		slog.Error("setup: failed to complete setup", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete setup"})
		return
	}

	slog.Info("setup: initial setup completed successfully")

	authMethod := "OIDC"
	if status.LDAPConfigured {
		authMethod = "LDAP"
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         fmt.Sprintf("Setup completed successfully. You can now log in via %s.", authMethod),
		"setup_completed": true,
	})
}

// === Scanning Configuration ===

// TestScanningConfigInput is the request body for testing a scanning configuration.
type TestScanningConfigInput struct {
	Tool            string `json:"tool" binding:"required"`
	BinaryPath      string `json:"binary_path" binding:"required"`
	ExpectedVersion string `json:"expected_version"`
}

// @Summary      Test scanning configuration
// @Description  Tests a security scanner configuration by verifying the binary exists and checking its version. Does NOT save anything.
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body  TestScanningConfigInput  true  "Scanning configuration to test"
// @Success      200  {object}  setup.TestScanningConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Router       /api/v1/setup/scanning/test [post]
func (h *Handlers) TestScanningConfig(c *gin.Context) {
	var input TestScanningConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate tool is one of the supported scanners
	validTools := map[string]bool{
		"trivy": true, "terrascan": true, "snyk": true, "checkov": true, "custom": true,
	}
	if !validTools[input.Tool] {
		c.JSON(http.StatusOK, TestScanningConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported tool %q; must be one of: trivy, terrascan, snyk, checkov, custom", input.Tool),
		})
		return
	}

	// Check binary exists
	if _, err := os.Stat(input.BinaryPath); err != nil {
		c.JSON(http.StatusOK, TestScanningConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("binary not found at %q: %v", input.BinaryPath, err),
		})
		return
	}

	// Build a temporary ScanningConfig and create a scanner
	scanCfg := config.ScanningConfig{
		Tool:       input.Tool,
		BinaryPath: input.BinaryPath,
		Timeout:    30 * time.Second,
	}
	s, err := scanner.New(&scanCfg)
	if err != nil {
		c.JSON(http.StatusOK, TestScanningConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to initialize scanner: %v", err),
		})
		return
	}

	// Get version with a timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	version, err := s.Version(ctx)
	if err != nil {
		c.JSON(http.StatusOK, TestScanningConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to get scanner version: %v", err),
		})
		return
	}

	// Compare expected version if set
	if input.ExpectedVersion != "" && version != input.ExpectedVersion {
		c.JSON(http.StatusOK, TestScanningConfigResponse{
			Success:         false,
			DetectedVersion: version,
			Error:           fmt.Sprintf("version mismatch: expected %q but got %q", input.ExpectedVersion, version),
		})
		return
	}

	c.JSON(http.StatusOK, TestScanningConfigResponse{
		Success:         true,
		DetectedVersion: version,
	})
}

// SaveScanningConfigInput is the request body for saving a scanning configuration.
type SaveScanningConfigInput struct {
	Enabled         bool   `json:"enabled"`
	Tool            string `json:"tool" binding:"required"`
	BinaryPath      string `json:"binary_path" binding:"required"`
	ExpectedVersion string `json:"expected_version"`
	TimeoutSecs     int    `json:"timeout_secs"`
	WorkerCount     int    `json:"worker_count"`
}

// @Summary      Save scanning configuration
// @Description  Saves security scanning configuration to the database and marks scanning as configured.
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body  SaveScanningConfigInput  true  "Scanning configuration to save"
// @Success      200  {object}  setup.SaveScanningConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/setup/scanning [post]
func (h *Handlers) SaveScanningConfig(c *gin.Context) {
	var input SaveScanningConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate binary_path is within the managed install directory.
	// This prevents arbitrary executables from being registered as scanners.
	if h.cfg.Scanning.InstallDir != "" {
		cleanBinary := filepath.Clean(input.BinaryPath)
		cleanInstall := filepath.Clean(h.cfg.Scanning.InstallDir)
		if !strings.HasPrefix(cleanBinary, cleanInstall+string(filepath.Separator)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "binary_path must be within the scanner install directory"})
			return
		}
	}

	// Verify the binary exists on disk before saving.
	if _, err := os.Stat(input.BinaryPath); err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "binary_path does not exist"})
		} else {
			slog.Error("setup: failed to stat binary_path", "path", input.BinaryPath, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify binary_path"})
		}
		return
	}

	ctx := c.Request.Context()

	// Serialize the input to JSON for storage
	jsonBytes, err := json.Marshal(input)
	if err != nil {
		slog.Error("setup: failed to serialize scanning config", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize scanning configuration"})
		return
	}

	// Save to database
	if err := h.oidcConfigRepo.SetScanningConfig(ctx, jsonBytes); err != nil {
		slog.Error("setup: failed to save scanning config", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save scanning configuration"})
		return
	}

	// Update the in-memory config so the scanner job and config endpoint reflect
	// the new settings immediately, without requiring a pod restart.
	h.cfg.Scanning.Enabled = input.Enabled
	h.cfg.Scanning.Tool = input.Tool
	h.cfg.Scanning.BinaryPath = input.BinaryPath
	h.cfg.Scanning.ExpectedVersion = input.ExpectedVersion
	if input.TimeoutSecs > 0 {
		h.cfg.Scanning.Timeout = time.Duration(input.TimeoutSecs) * time.Second
	}
	if input.WorkerCount > 0 {
		h.cfg.Scanning.WorkerCount = input.WorkerCount
	}

	slog.Info("setup: scanning configuration saved", "tool", input.Tool, "enabled", input.Enabled)

	c.JSON(http.StatusOK, SaveScanningConfigResponse{
		Message: "Scanning configuration saved",
	})
}

// @Summary      Test LDAP configuration
// @Description  Tests an LDAP configuration by attempting a bind with the service account credentials. Does NOT save anything.
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body  models.LDAPConfigInput  true  "LDAP configuration to test"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Router       /api/v1/setup/ldap/test [post]
func (h *Handlers) TestLDAPConfig(c *gin.Context) {
	var input models.LDAPConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateLDAPInput(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build a temporary LDAPConfig to test connectivity
	testCfg := ldapInputToConfig(&input)

	provider, err := ldappkg.NewProvider(testCfg)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": fmt.Sprintf("LDAP configuration error: %v", err),
		})
		return
	}
	defer provider.Close()

	// Test with a bind operation — the provider validates connectivity on creation
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("LDAP connection to %s:%d succeeded. Service account bind verified.", input.Host, testCfg.Port),
	})
}

// @Summary      Save LDAP configuration
// @Description  Saves LDAP configuration and activates LDAP as the authentication method. OIDC and LDAP are mutually exclusive.
// @Tags         Setup
// @Security     SetupToken
// @Accept       json
// @Produce      json
// @Param        body  body  models.LDAPConfigInput  true  "LDAP configuration to save"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration"
// @Failure      401  {object}  map[string]interface{}  "Invalid setup token"
// @Failure      403  {object}  map[string]interface{}  "Setup already completed"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/setup/ldap [post]
func (h *Handlers) SaveLDAPConfig(c *gin.Context) {
	var input models.LDAPConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateLDAPInput(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Encrypt the bind password before storing
	encryptedPassword, err := h.tokenCipher.Seal(input.BindPassword)
	if err != nil {
		slog.Error("setup: failed to encrypt LDAP bind password", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt bind password"})
		return
	}

	// Build a safe copy for storage (encrypted password, no plaintext)
	storedConfig := map[string]interface{}{
		"host":                 input.Host,
		"port":                 input.Port,
		"use_tls":              input.UseTLS,
		"start_tls":            input.StartTLS,
		"insecure_skip_verify": input.InsecureSkipVerify,
		"bind_dn":              input.BindDN,
		"bind_password_enc":    encryptedPassword,
		"base_dn":              input.BaseDN,
		"user_filter":          input.UserFilter,
		"user_attr_email":      input.UserAttrEmail,
		"user_attr_name":       input.UserAttrName,
		"group_base_dn":        input.GroupBaseDN,
		"group_filter":         input.GroupFilter,
		"group_member_attr":    input.GroupMemberAttr,
	}

	jsonBytes, err := json.Marshal(storedConfig)
	if err != nil {
		slog.Error("setup: failed to serialize LDAP config", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize LDAP configuration"})
		return
	}

	if err := h.oidcConfigRepo.SetLDAPConfig(ctx, jsonBytes); err != nil {
		slog.Error("setup: failed to save LDAP config", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save LDAP configuration"})
		return
	}

	// Also mark OIDC as configured (auth is configured via LDAP)
	if err := h.oidcConfigRepo.SetOIDCConfigured(ctx); err != nil {
		slog.Error("setup: failed to mark auth as configured", "error", err)
	}

	// Instantiate and swap the live LDAP provider
	liveCfg := ldapInputToConfig(&input)
	liveProvider, err := ldappkg.NewProvider(liveCfg)
	if err != nil {
		slog.Warn("setup: LDAP config saved but live provider initialization failed",
			"error", err, "host", input.Host)
	} else {
		if h.authHandlers != nil {
			h.authHandlers.SetLDAPProvider(liveProvider)
		}
		slog.Info("setup: LDAP provider activated", "host", input.Host)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "LDAP configuration saved and activated",
		"host":    input.Host,
		"port":    input.Port,
	})
}

// ldapInputToConfig converts a LDAPConfigInput to the config.LDAPConfig used by the auth provider.
func ldapInputToConfig(input *models.LDAPConfigInput) *config.LDAPConfig {
	port := input.Port
	if port == 0 {
		if input.UseTLS {
			port = 636
		} else {
			port = 389
		}
	}
	userAttrEmail := input.UserAttrEmail
	if userAttrEmail == "" {
		userAttrEmail = "mail"
	}
	userAttrName := input.UserAttrName
	if userAttrName == "" {
		userAttrName = "displayName"
	}
	groupMemberAttr := input.GroupMemberAttr
	if groupMemberAttr == "" {
		groupMemberAttr = "member"
	}

	return &config.LDAPConfig{
		Enabled:            true,
		Host:               input.Host,
		Port:               port,
		UseTLS:             input.UseTLS,
		StartTLS:           input.StartTLS,
		InsecureSkipVerify: input.InsecureSkipVerify,
		BindDN:             input.BindDN,
		BindPassword:       input.BindPassword,
		BaseDN:             input.BaseDN,
		UserFilter:         input.UserFilter,
		UserAttrEmail:      userAttrEmail,
		UserAttrName:       userAttrName,
		GroupBaseDN:        input.GroupBaseDN,
		GroupFilter:        input.GroupFilter,
		GroupMemberAttr:    groupMemberAttr,
	}
}

// validateLDAPInput validates required fields for LDAP configuration
func validateLDAPInput(input *models.LDAPConfigInput) error {
	if input.Host == "" {
		return fmt.Errorf("host is required")
	}
	if input.BindDN == "" {
		return fmt.Errorf("bind_dn is required")
	}
	if input.BindPassword == "" {
		return fmt.Errorf("bind_password is required")
	}
	if input.BaseDN == "" {
		return fmt.Errorf("base_dn is required")
	}
	if input.UserFilter == "" {
		return fmt.Errorf("user_filter is required")
	}
	if input.Port < 0 || input.Port > 65535 {
		return fmt.Errorf("port must be between 0 and 65535")
	}
	return nil
}

// === Helper functions ===

// validateOIDCInput validates required fields for OIDC configuration
func validateOIDCInput(input *models.OIDCConfigInput) error {
	if input.IssuerURL == "" {
		return fmt.Errorf("issuer_url is required")
	}
	if !strings.HasPrefix(input.IssuerURL, "https://") && !strings.HasPrefix(input.IssuerURL, "http://") {
		return fmt.Errorf("issuer_url must be a valid URL starting with https:// or http://")
	}
	if input.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if input.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	if input.RedirectURL == "" {
		return fmt.Errorf("redirect_url is required")
	}
	if input.ProviderType == "" {
		input.ProviderType = "generic_oidc"
	}
	if input.ProviderType != "generic_oidc" && input.ProviderType != "azuread" {
		return fmt.Errorf("provider_type must be 'generic_oidc' or 'azuread'")
	}
	return nil
}

// buildTestStorageConfig builds a temporary config for testing storage connectivity
func buildTestStorageConfig(input *models.StorageConfigInput) *config.Config {
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
	return testCfg
}

// buildEncryptedStorageConfig creates a StorageConfig model with encrypted sensitive fields
func (h *Handlers) buildEncryptedStorageConfig(input *models.StorageConfigInput) (*models.StorageConfig, error) {
	now := time.Now()
	cfg := &models.StorageConfig{
		ID:          uuid.New(),
		BackendType: input.BackendType,
		IsActive:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	switch input.BackendType {
	case "local":
		cfg.LocalBasePath = toNullString(input.LocalBasePath)
		if input.LocalServeDirectly != nil {
			cfg.LocalServeDirectly = sql.NullBool{Bool: *input.LocalServeDirectly, Valid: true}
		}
	case "azure":
		cfg.AzureAccountName = toNullString(input.AzureAccountName)
		cfg.AzureContainerName = toNullString(input.AzureContainerName)
		cfg.AzureCDNURL = toNullString(input.AzureCDNURL)
		if input.AzureAccountKey != "" {
			encrypted, err := h.tokenCipher.Seal(input.AzureAccountKey)
			if err != nil {
				return nil, err
			}
			cfg.AzureAccountKeyEncrypted = toNullString(encrypted)
		}
	case "s3":
		cfg.S3Endpoint = toNullString(input.S3Endpoint)
		cfg.S3Region = toNullString(input.S3Region)
		cfg.S3Bucket = toNullString(input.S3Bucket)
		cfg.S3AuthMethod = toNullString(input.S3AuthMethod)
		cfg.S3RoleARN = toNullString(input.S3RoleARN)
		cfg.S3RoleSessionName = toNullString(input.S3RoleSessionName)
		cfg.S3ExternalID = toNullString(input.S3ExternalID)
		cfg.S3WebIdentityTokenFile = toNullString(input.S3WebIdentityTokenFile)
		if input.S3AccessKeyID != "" {
			encrypted, err := h.tokenCipher.Seal(input.S3AccessKeyID)
			if err != nil {
				return nil, err
			}
			cfg.S3AccessKeyIDEncrypted = toNullString(encrypted)
		}
		if input.S3SecretAccessKey != "" {
			encrypted, err := h.tokenCipher.Seal(input.S3SecretAccessKey)
			if err != nil {
				return nil, err
			}
			cfg.S3SecretAccessKeyEncrypted = toNullString(encrypted)
		}
	case "gcs":
		cfg.GCSBucket = toNullString(input.GCSBucket)
		cfg.GCSProjectID = toNullString(input.GCSProjectID)
		cfg.GCSAuthMethod = toNullString(input.GCSAuthMethod)
		cfg.GCSCredentialsFile = toNullString(input.GCSCredentialsFile)
		cfg.GCSEndpoint = toNullString(input.GCSEndpoint)
		if input.GCSCredentialsJSON != "" {
			encrypted, err := h.tokenCipher.Seal(input.GCSCredentialsJSON)
			if err != nil {
				return nil, err
			}
			cfg.GCSCredentialsJSONEncrypted = toNullString(encrypted)
		}
	}

	return cfg, nil
}

func toNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
