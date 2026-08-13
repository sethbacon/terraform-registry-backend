// Package setup implements HTTP handlers for the first-run setup wizard.
// These endpoints are authenticated via setup token (not JWT/API key) and are
// permanently disabled after setup completes. They allow configuring OIDC,
// storage, and the initial admin user through the frontend wizard or via curl.
package setup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/audit"
	ldappkg "github.com/terraform-registry/terraform-registry/internal/auth/ldap"
	"github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
	"github.com/terraform-registry/terraform-registry/internal/safego"
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
	authHandlers      *admin.AuthHandlers // to swap OIDC provider at runtime
	installFunc       installer.InstallFunc
	scannerJob        *jobs.ModuleScannerJob
	egressGuard       *httpsafe.Guard
	// carrier is where the bootstrap administrator is recorded, and from
	// migration 000054 it is the ONLY place platform-admin authority lives
	// (issue #766). See WithPlatformAdminCarrier.
	carrier *repositories.PlatformAdminRepository
	// outbox carries that grant's audit intent into the same transaction;
	// migration 000052's constraint trigger refuses the commit without one.
	outbox *audit.Outbox
}

// WithPlatformAdminCarrier attaches the platform-admin carrier the setup
// wizard establishes invariant A with. It is not optional from migration
// 000054: without it ConfigureAdmin has nothing to grant and fails.
//
// Injected rather than built from a repo this struct already holds, for the
// same reason NewOrganizationHandlers takes claimRepo as a parameter: the
// carrier is on the REGISTRY's connection (migration 000051) while every
// other repository here is on identity's, and under
// TFR_IDENTITY_DATABASE_* those are different physical databases.
//
// The outbox comes with it and is on that same registry connection, because
// the grant and the record of the grant have to commit together (migration
// 000052). Passing the carrier without it produces a bootstrap that cannot
// commit, which is why they are one argument list rather than two setters.
func (h *Handlers) WithPlatformAdminCarrier(carrier *repositories.PlatformAdminRepository, outbox *audit.Outbox) *Handlers {
	h.carrier = carrier
	h.outbox = outbox
	return h
}

// WithScannerJob attaches the scanner job so that SaveScanningConfig can kick
// it off immediately after enabling scanning at runtime, without requiring a
// server restart.
func (h *Handlers) WithScannerJob(job *jobs.ModuleScannerJob) *Handlers {
	h.scannerJob = job
	return h
}

// WithEgressGuard attaches the operator-configured egress guard so that
// InstallScanner's installer.Handle call routes its downloads through the
// shared httpsafe policy (issue #676); nil is the strict default.
func (h *Handlers) WithEgressGuard(g *httpsafe.Guard) *Handlers {
	h.egressGuard = g
	return h
}

// NewHandlers creates a new setup Handlers instance.
func NewHandlers(
	cfg *config.Config,
	tokenCipher *crypto.TokenCipher,
	oidcConfigRepo *repositories.OIDCConfigRepository,
	storageConfigRepo *repositories.StorageConfigRepository,
	userRepo *repositories.UserRepository,
	authHandlers *admin.AuthHandlers,
) *Handlers {
	return &Handlers{
		cfg:               cfg,
		tokenCipher:       tokenCipher,
		oidcConfigRepo:    oidcConfigRepo,
		storageConfigRepo: storageConfigRepo,
		userRepo:          userRepo,
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

	// The row id is minted here rather than at the struct literal below, because
	// the client secret is sealed against it (suite-identity #153) and the seal
	// happens first. CreateOIDCConfig takes the id from the caller, so the row
	// can be bound from its only write and never exists in the unbound form.
	oidcConfigID := uuid.New()

	// Encrypt the client secret, bound to the row it will live in
	encryptedSecret, err := h.tokenCipher.SealWithContext(input.ClientSecret,
		models.OIDCConfigClientSecretContext(oidcConfigID.String()))
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

	// Create the new OIDC config. As of terraform-suite-identity v0.17.0,
	// CreateOIDCConfig itself wraps the insert in a deactivate-all-then-
	// activate-one transaction whenever IsActive is true (the same transaction
	// ActivateOIDCConfig uses), so the single-active-config invariant is
	// enforced atomically at write time. The previously-separate explicit
	// DeactivateAllOIDCConfigs call is no longer needed here — keeping it would
	// just reintroduce the transient "zero active configs" window between two
	// non-atomic calls that this transaction is designed to close.
	now := time.Now()
	oidcCfg := &models.OIDCConfig{
		ID:                     oidcConfigID,
		Name:                   name,
		ProviderType:           input.ProviderType,
		IssuerURL:              input.IssuerURL,
		ClientID:               input.ClientID,
		ClientSecretCiphertext: encryptedSecret,
		RedirectURL:            input.RedirectURL,
		Scopes:                 scopesJSON,
		IsActive:               true,
		ExtraConfig:            extraConfigJSON,
		CreatedAt:              now,
		UpdatedAt:              now,
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

	c.JSON(http.StatusOK, models.OIDCConfigToResponse(oidcCfg))
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
// probeEgressAllowed reports whether the setup wizard may dial target, which is
// either a URL (S3/GCS endpoint) or a "host:port" (LDAP).
//
// internal/httpsafe guards the HTTP clients this application constructs itself.
// These two probes go out through clients it does NOT construct -- the cloud
// SDK's own transport for a caller-supplied endpoint, and a raw LDAP TCP dial
// -- so neither passed through the egress policy that every other outbound
// request obeys, and both reached loopback, RFC1918 and link-local targets
// (issue #749).
//
// Fails CLOSED when no guard is configured. The alternative is that a
// deployment which never called WithEgressGuard silently keeps the old
// behaviour, which is the failure mode worth preventing: the guard was already
// stored on Handlers and simply never consulted.
func (h *Handlers) probeEgressAllowed(ctx context.Context, target string) error {
	if h.egressGuard == nil {
		return fmt.Errorf("egress guard not configured")
	}
	if strings.Contains(target, "://") {
		return h.egressGuard.ValidateURL(target)
	}
	return h.egressGuard.ValidateHostPort(ctx, target)
}

// probeFailure renders a connectivity failure WITHOUT the transport error.
//
// The handlers used to echo err.Error() verbatim, which distinguishes
// "connection refused" from "timeout" from a protocol error -- an internal
// port-scan oracle for anyone holding the first-run setup token. The detail is
// logged server-side, where the operator running setup can still read it.
func probeFailure(c *gin.Context, what string, err error) {
	slog.Warn("setup: connectivity probe failed", "probe", what, "error", err)
	c.JSON(http.StatusOK, gin.H{
		"success": false,
		"message": what + " connectivity test failed. See the server logs for details.",
	})
}

func (h *Handlers) TestStorageConfig(c *gin.Context) {
	var input models.StorageConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build a temporary config from input
	testCfg := buildTestStorageConfig(&input)

	// Probe with a 10-second timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// A caller-supplied endpoint is dialed by the cloud SDK's own transport,
	// which httpsafe does not wrap -- so it is checked here, before the backend
	// is instantiated (issue #749). An empty endpoint means the SDK's default
	// public endpoint, which needs no check.
	// AzureCDNURL is here too even though the issue named only S3/GCS: it is
	// the same shape -- a caller-supplied URL the SDK dials on its own
	// transport.
	for _, endpoint := range []string{input.S3Endpoint, input.GCSEndpoint, input.AzureCDNURL} {
		if endpoint == "" {
			continue
		}
		if err := h.probeEgressAllowed(ctx, endpoint); err != nil {
			slog.Warn("setup: storage endpoint rejected by egress policy",
				"endpoint", endpoint, "error", err)
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "Storage endpoint is not permitted by the server's egress policy.",
			})
			return
		}
	}

	// Instantiate the backend
	backend, err := storage.NewStorage(testCfg)
	if err != nil {
		probeFailure(c, "Storage", err)
		return
	}

	if _, probeErr := backend.Exists(ctx, ".connectivity-test"); probeErr != nil {
		probeFailure(c, "Storage", probeErr)
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

// errNoPlatformAdminCarrier is returned when the wizard was built without the
// platform-admin carrier. It is a wiring fault, not a database fault, and from
// migration 000054 it is fatal to setup: the carrier is the only thing
// ConfigureAdmin grants.
var errNoPlatformAdminCarrier = errors.New("no platform-admin carrier is wired")

// @Summary      Configure initial admin user
// @Description  Creates the initial admin user record and grants them platform administration through the platform_admins carrier. No organization membership is written: platform-admin authority no longer travels on a role template (issue #766). The email must match the OIDC identity that will be used for the first login.
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

	// BOOTSTRAP INVARIANT A (issue #766). THE ONLY GRANT THIS WIZARD MAKES.
	//
	// Until migration 000054 this handler wrote an organization_members row
	// pointing at the `admin` role template, and the carrier row beside it. The
	// membership is gone: a role template confers no platform-admin authority
	// any more, so writing one would be writing something that does nothing,
	// and it was the last remaining path by which the platform-wide wildcard
	// reached `organization_members` at all — PR #850's structural guard listed
	// it as a named exemption precisely because it could not be removed until
	// now.
	//
	// The bootstrap administrator therefore starts with NO organization
	// membership. That is not a gap: the carrier grants the `admin` wildcard on
	// every request, which is what every organization route already accepts,
	// and invariant B is vacuous over an organization with no members. They can
	// enrol themselves, or anyone else, through the member API immediately.
	//
	// granted_by is the user themselves rather than NULL: this grant IS
	// attributable, to whoever holds the one-time setup token, and NULL is
	// reserved by migration 000051 for rows nobody granted.
	//
	// FATAL, WHICH IT WAS NOT BEFORE. While the membership existed a failed
	// carrier write left a deployment that still had an administrator, so it
	// was reported and setup continued. Now it leaves a deployment with NO
	// administrator and no API route able to create one — the exact lockout the
	// rest of this release is built to prevent. Setup has not been marked
	// complete at this point, so the operator can simply retry.
	if err := h.recordBootstrapPlatformAdmin(ctx, user.ID, email); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to grant platform administration to the initial admin user; " +
				"the deployment would have no administrator. Fix the registry database connection and retry.",
		})
		return
	}

	// Store the pending admin email for email-matching during first OIDC login
	if err := h.oidcConfigRepo.SetPendingAdminEmail(ctx, email); err != nil {
		slog.Error("setup: failed to set pending admin email", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Admin user configured successfully",
		"email":          email,
		"platform_admin": true,
	})
}

// recordBootstrapPlatformAdmin writes the bootstrap administrator's
// platform_admins row and returns nil when the grant stands (issue #766).
//
// Idempotent: a second run of the wizard, or a deployment whose migration
// 000051/000054 backfill already captured this person, reports
// ErrAlreadyPlatformAdmin — which is a SUCCESS here. The row exists, which is
// the only thing the invariant cares about, and re-granting would rewrite the
// provenance the carrier exists to keep.
func (h *Handlers) recordBootstrapPlatformAdmin(ctx context.Context, userID, email string) error {
	if h.carrier == nil {
		slog.Error("setup: no platform-admin carrier wired; this deployment would have no "+
			"administrator at all", "email", email)
		return errNoPlatformAdminCarrier
	}
	note := "bootstrap administrator configured by the setup wizard"
	resourceType := repositories.AuditResourcePlatformAdmin
	target := userID
	intent := &audit.Intent{
		Action:       repositories.AuditActionPlatformAdminGranted,
		ActorUserID:  &target,
		ActorEmail:   &email,
		ResourceType: &resourceType,
		ResourceID:   &target,
		Metadata: map[string]interface{}{
			"target_user_id":    userID,
			"target_user_email": email,
			"note":              note,
			"bootstrap":         true,
		},
	}
	// The intent commits with the grant or neither does (migration 000052).
	// ActorUserID is the new administrator themselves, matching granted_by
	// below: the acting principal is whoever holds the one-time setup token,
	// who has no user row of their own, and naming the subject is the only
	// attribution that is true.
	_, err := h.carrier.Grant(ctx, userID, &userID, &note, func(ctx context.Context, tx *sql.Tx) error {
		return h.outbox.Enqueue(ctx, tx, intent)
	})
	if err == nil || errors.Is(err, repositories.ErrAlreadyPlatformAdmin) {
		slog.Info("setup: bootstrap administrator recorded in the platform-admin carrier",
			"user_id", userID, "email", email)
		return nil
	}
	slog.Error("setup: failed to record the bootstrap administrator in the platform-admin carrier; "+
		"nothing else in this wizard grants platform administration, so the deployment has none",
		"user_id", userID, "email", email, "error", err)
	return err
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

// validScanningTools is the allowlist of supported scanner backends. Any code
// path that accepts a Tool value from outside the binary (HTTP body, DB row)
// MUST validate against this set before the value flows into filesystem or
// process-invocation paths — see internal/scanner.ResolveBinaryPath, which
// joins InstallDir + Tool when falling back from a missing BinaryPath.
var validScanningTools = map[string]bool{
	"trivy":     true,
	"terrascan": true,
	"snyk":      true,
	"checkov":   true,
	"custom":    true,
}

// IsValidScanningTool reports whether tool is in the supported-scanners allowlist.
// Exported so the router's startup-reload path can re-validate persisted DB values
// before they are written into the live config.
func IsValidScanningTool(tool string) bool {
	return validScanningTools[tool]
}

const supportedScanningToolsList = "trivy, terrascan, snyk, checkov, custom"

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

	// Validate tool is one of the supported scanners.
	if !IsValidScanningTool(input.Tool) {
		c.JSON(http.StatusOK, TestScanningConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported tool %q; must be one of: %s", input.Tool, supportedScanningToolsList),
		})
		return
	}

	// Validate binary_path is within the managed install directory.
	// This prevents the test endpoint from being used to probe arbitrary
	// executables on the host filesystem.
	if h.cfg.Scanning.InstallDir != "" {
		cleanBinary := filepath.Clean(input.BinaryPath)
		cleanInstall := filepath.Clean(h.cfg.Scanning.InstallDir)
		if !strings.HasPrefix(cleanBinary, cleanInstall+string(filepath.Separator)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "binary_path must be within the scanner install directory"})
			return
		}
	}

	// Check binary exists
	if _, err := os.Stat(input.BinaryPath); err != nil { // #nosec G304 -- BinaryPath constrained to InstallDir above; operator-managed directory only
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

	// Validate tool is one of the supported scanners. Without this, an arbitrary
	// Tool value would be persisted and later flow into filepath.Join(InstallDir,
	// Tool) at scanner startup (see internal/scanner.ResolveBinaryPath).
	if !IsValidScanningTool(input.Tool) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("unsupported tool %q; must be one of: %s", input.Tool, supportedScanningToolsList),
		})
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

	// If scanning was just enabled at runtime, kick off the scanner job so that
	// pending scans are processed immediately without a server restart.
	if input.Enabled && h.scannerJob != nil {
		safego.Go(func() {
			if err := h.scannerJob.Start(context.Background()); err != nil {
				slog.Warn("setup: scanner job failed to start after config save", "error", err)
			}
		})
	}

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

	// The LDAP provider dials host:port directly over TCP, with no HTTP client
	// for httpsafe to wrap, so the deny-list is applied here (issue #749).
	// validateLDAPInput only checks non-emptiness and the port range.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	target := net.JoinHostPort(testCfg.Host, strconv.Itoa(testCfg.Port))
	if err := h.probeEgressAllowed(ctx, target); err != nil {
		slog.Warn("setup: LDAP target rejected by egress policy",
			"target", target, "error", err)
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "LDAP host is not permitted by the server's egress policy.",
		})
		return
	}

	provider, err := ldappkg.NewProvider(testCfg)
	if err != nil {
		probeFailure(c, "LDAP", err)
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
	encryptedPassword, err := h.tokenCipher.SealWithContext(input.BindPassword,
		models.SystemSettingsLDAPBindPasswordContext())
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
			encrypted, err := h.tokenCipher.SealWithContext(input.AzureAccountKey,
				models.StorageConfigAzureAccountKeyContext(cfg.ID.String()))
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
			encrypted, err := h.tokenCipher.SealWithContext(input.S3AccessKeyID,
				models.StorageConfigS3AccessKeyIDContext(cfg.ID.String()))
			if err != nil {
				return nil, err
			}
			cfg.S3AccessKeyIDEncrypted = toNullString(encrypted)
		}
		if input.S3SecretAccessKey != "" {
			encrypted, err := h.tokenCipher.SealWithContext(input.S3SecretAccessKey,
				models.StorageConfigS3SecretAccessKeyContext(cfg.ID.String()))
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
			encrypted, err := h.tokenCipher.SealWithContext(input.GCSCredentialsJSON,
				models.StorageConfigGCSCredentialsJSONContext(cfg.ID.String()))
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
