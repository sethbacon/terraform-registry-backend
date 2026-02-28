// Package api wires together all HTTP routes for the Terraform Registry backend.
//
// Route grouping philosophy:
//   - Terraform protocol routes (/v1/modules/, /v1/providers/, /v1/mirror/) are
//     intentionally unauthenticated. The HashiCorp protocol specification requires
//     these to be publicly accessible so that `terraform init` can resolve modules
//     and providers without supplying credentials at the discovery stage.
//   - Admin and upload routes (/api/v1/) always require authentication and the
//     appropriate RBAC scope.
//
// The Swagger UI at /api-docs/ uses a nonce-based Content Security Policy rather
// than hash-based CSP. The CDN-loaded Swagger UI bundle contains inline <script>
// elements whose hashes would change with every CDN version update. A per-request
// cryptographic nonce allows those inline scripts to execute while keeping the
// CSP strict for all other content.
package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/docs"
	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/api/mirror"
	"github.com/terraform-registry/terraform-registry/internal/api/modules"
	"github.com/terraform-registry/terraform-registry/internal/api/providers"
	"github.com/terraform-registry/terraform-registry/internal/api/setup"
	terraform_binaries "github.com/terraform-registry/terraform-registry/internal/api/terraform_binaries"
	"github.com/terraform-registry/terraform-registry/internal/api/webhooks"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
	"github.com/terraform-registry/terraform-registry/internal/services"
	"github.com/terraform-registry/terraform-registry/internal/storage"

	// Import storage backends to register them
	_ "github.com/terraform-registry/terraform-registry/internal/storage/azure"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/gcs"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/local"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/s3"

	// Import SCM connectors to register them via init()
	_ "github.com/terraform-registry/terraform-registry/internal/scm/azuredevops"
	_ "github.com/terraform-registry/terraform-registry/internal/scm/bitbucket"
	_ "github.com/terraform-registry/terraform-registry/internal/scm/github"
	_ "github.com/terraform-registry/terraform-registry/internal/scm/gitlab"
)

// BackgroundServices holds references to background jobs and resources that must
// be stopped during graceful shutdown. The caller (cmd/server) is responsible for
// calling Shutdown() when the process receives a termination signal.
type BackgroundServices struct {
	mirrorSyncJob   *jobs.MirrorSyncJob
	tfMirrorSyncJob *jobs.TerraformMirrorSyncJob
	expiryNotifier  *jobs.APIKeyExpiryNotifier
	rateLimiters    []*middleware.RateLimiter
}

// Shutdown stops all background goroutines. It should be called after the HTTP
// server has been shut down so that in-flight requests are drained first.
func (bg *BackgroundServices) Shutdown() {
	slog.Info("stopping background services")
	if bg.mirrorSyncJob != nil {
		bg.mirrorSyncJob.Stop()
	}
	if bg.tfMirrorSyncJob != nil {
		bg.tfMirrorSyncJob.Stop()
	}
	if bg.expiryNotifier != nil {
		bg.expiryNotifier.Stop()
	}
	for _, rl := range bg.rateLimiters {
		rl.Stop()
	}
	slog.Info("all background services stopped")
}

// NewRouter creates and configures the Gin router
func NewRouter(cfg *config.Config, db *sql.DB) (*gin.Engine, *BackgroundServices) {
	router := gin.New()

	// Initialize storage backend
	storageBackend, err := storage.NewStorage(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize storage backend: %v", err)
	}
	log.Printf("Initialized storage backend: %s", cfg.Storage.DefaultBackend)

	// Initialize repositories
	userRepo := repositories.NewUserRepository(db)
	apiKeyRepo := repositories.NewAPIKeyRepository(db)
	moduleRepo := repositories.NewModuleRepository(db)
	providerRepo := repositories.NewProviderRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	orgRepo := repositories.NewOrganizationRepository(db)

	// Wrap *sql.DB with sqlx for SCM and mirror repositories
	sqlxDB := sqlx.NewDb(db, "postgres")
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	mirrorRepo := repositories.NewMirrorRepository(sqlxDB)
	storageConfigRepo := repositories.NewStorageConfigRepository(sqlxDB)
	oidcConfigRepo := repositories.NewOIDCConfigRepository(sqlxDB)

	// Initialize mirror sync job
	mirrorSyncJob := jobs.NewMirrorSyncJob(mirrorRepo, providerRepo, orgRepo, storageBackend, cfg.Storage.DefaultBackend)
	// Start background sync job - check every 10 minutes for mirrors that need syncing
	mirrorSyncJob.Start(context.Background(), 10)
	log.Println("Mirror sync job started (checking every 10 minutes)")

	// Initialize Terraform binary mirror repository and sync job
	tfMirrorRepo := repositories.NewTerraformMirrorRepository(sqlxDB)
	tfMirrorSyncJob := jobs.NewTerraformMirrorSyncJob(tfMirrorRepo, storageBackend, cfg.Storage.DefaultBackend)
	tfMirrorSyncJob.Start(context.Background(), 10)
	log.Println("Terraform binary mirror sync job started (checking every 10 minutes)")

	// Public handler is created here (before route registration)
	tfBinariesHandler := terraform_binaries.NewHandler(tfMirrorRepo, storageBackend)

	// Initialize and start the API key expiry notifier
	expiryNotifier := jobs.NewAPIKeyExpiryNotifier(apiKeyRepo, userRepo, &cfg.Notifications)
	go expiryNotifier.Start(context.Background())
	log.Println("API key expiry notifier started")

	// Get encryption key from environment for OAuth token encryption
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		log.Fatal("ENCRYPTION_KEY environment variable must be set for SCM integration")
	}

	// Initialize token cipher for encrypting OAuth tokens
	tokenCipher, err := crypto.NewTokenCipher([]byte(encryptionKey))
	if err != nil {
		log.Fatalf("Failed to initialize token cipher: %v", err)
	}

	// Add middleware
	router.Use(gin.Recovery())
	router.Use(middleware.RequestIDMiddleware())
	router.Use(middleware.MetricsMiddleware())
	router.Use(LoggerMiddleware(cfg))
	router.Use(CORSMiddleware(cfg))
	router.Use(middleware.SecurityHeadersMiddleware(middleware.APISecurityHeadersConfig()))

	// Health check endpoint
	router.GET("/health", healthCheckHandler(db))

	// Readiness check endpoint (includes storage backend probe)
	router.GET("/ready", readinessHandler(db, storageBackend))

	// Service discovery endpoint (Terraform protocol)
	router.GET("/.well-known/terraform.json", serviceDiscoveryHandler(cfg))

	// API version
	router.GET("/version", versionHandler())

	// Swagger UI - serve from CDN
	serveSwaggerUI := func(c *gin.Context) {
		// Generate a per-request nonce for CSP
		nb := make([]byte, 16)
		if _, err := rand.Read(nb); err != nil {
			c.String(http.StatusInternalServerError, "failed to generate nonce")
			return
		}
		nonce := base64.StdEncoding.EncodeToString(nb)

		// Allow same-origin framing so the frontend React app can embed this page
		c.Header("X-Frame-Options", "SAMEORIGIN")

		// Set a nonce-based Content Security Policy allowing the generated
		// nonce for inline scripts and styles. This is safe for serving the
		// Swagger UI page while keeping the global API CSP strict.
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Security-Policy", fmt.Sprintf(
			"default-src 'self' https:; script-src 'self' 'nonce-%s' https:; style-src 'self' 'nonce-%s' https:; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:",
			nonce, nonce,
		))

		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
	<head>
		<title>Swagger UI</title>
		<meta charset="utf-8"/>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui.min.css">
		<style nonce="%s">
			html{
				box-sizing: border-box;
				overflow: -moz-scrollbars-vertical;
				overflow-y: scroll;
			}
			*,
			*:before,
			*:after{
				box-sizing: inherit;
			}
			body {@font-family: sans-serif;
				color: #fafafa;
			}
		</style>
	</head>

	<body>
		<div id="swagger-ui"></div>

		<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui-bundle.min.js" crossorigin></script>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui-standalone-preset.min.js" crossorigin></script>
		<script nonce="%s">
		window.onload = function() {
			const ui = SwaggerUIBundle({
				url: "/swagger.json",
				dom_id: '#swagger-ui',
				deepLinking: true,
				presets: [
					SwaggerUIBundle.presets.apis,
					SwaggerUIBundle.SwaggerUIStandalonePreset
				],
				plugins: [
					SwaggerUIBundle.plugins.DownloadUrl
				],
				layout: "BaseLayout",
				docExpansion: "list"
			})
			window.ui = ui
		}
	</script>
	</body>
</html>`, nonce, nonce)

		c.Data(200, "text/html; charset=utf-8", []byte(html))
	}

	// Register both exact and trailing-slash routes for Swagger UI
	router.GET("/api-docs/index.html", serveSwaggerUI)
	router.GET("/api-docs/", serveSwaggerUI)
	// Redirect /api-docs -> /api-docs/
	router.GET("/api-docs", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/api-docs/")
	})

	// Raw Swagger JSON endpoint - serve embedded spec with runtime metadata
	router.GET("/swagger.json", func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.Header("Access-Control-Allow-Origin", "*")

		data := docs.SwaggerJSON

		// Unmarshal to a generic map so we can override the info fields
		var doc map[string]interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			log.Printf("failed to unmarshal swagger.json: %v", err)
			c.Data(http.StatusOK, "application/json", data)
			return
		}

		// Ensure info object exists
		info, _ := doc["info"].(map[string]interface{})
		if info == nil {
			info = map[string]interface{}{}
			doc["info"] = info
		}

		// Inject configured metadata if provided
		if cfg.ApiDocs.TermsOfService != "" {
			info["termsOfService"] = cfg.ApiDocs.TermsOfService
		}
		// Contact
		contact, _ := info["contact"].(map[string]interface{})
		if contact == nil {
			contact = map[string]interface{}{}
			info["contact"] = contact
		}
		if cfg.ApiDocs.ContactName != "" {
			contact["name"] = cfg.ApiDocs.ContactName
		}
		if cfg.ApiDocs.ContactEmail != "" {
			contact["email"] = cfg.ApiDocs.ContactEmail
		}

		// License
		if cfg.ApiDocs.License != "" {
			license := map[string]interface{}{"name": cfg.ApiDocs.License}
			info["license"] = license
		}

		// Marshal back to JSON and return
		out, err := json.Marshal(doc)
		if err != nil {
			log.Printf("failed to marshal modified swagger.json: %v", err)
			c.Data(http.StatusOK, "application/json", data)
			return
		}

		c.Data(http.StatusOK, "application/json", out)
	})

	// Module Registry endpoints (v1) - Terraform Protocol
	// These are public endpoints that support optional authentication
	v1Modules := router.Group("/v1/modules")
	v1Modules.Use(middleware.OptionalAuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo))
	{
		v1Modules.GET("/:namespace/:name/:system/versions", modules.ListVersionsHandler(db, cfg))
		v1Modules.GET("/:namespace/:name/:system/:version/download", modules.DownloadHandler(db, storageBackend, cfg))
	}

	// File serving endpoint for local storage with ServeDirectly enabled
	router.GET("/v1/files/*filepath", modules.ServeFileHandler(storageBackend, cfg))

	// Provider Registry endpoints (v1)
	// These are for the standard Provider Registry Protocol
	v1Providers := router.Group("/v1/providers")
	v1Providers.Use(middleware.OptionalAuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo))
	{
		v1Providers.GET("/:namespace/:type/versions", providers.ListVersionsHandler(db, cfg))
		v1Providers.GET("/:namespace/:type/:version/download/:os/:arch", providers.DownloadHandler(db, storageBackend, cfg))
	}

	// Network Mirror endpoints (separate from Provider Registry to avoid routing conflicts)
	// These endpoints include the hostname of the origin registry as per the Network Mirror Protocol
	// They use a different path structure: /terraform/providers/:hostname/:namespace/:type/...
	v1Mirror := router.Group("/terraform/providers")
	{
		v1Mirror.GET("/:hostname/:namespace/:type/index.json", mirror.IndexHandler(db, cfg))
		v1Mirror.GET("/:hostname/:namespace/:type/:versionfile", mirror.PlatformIndexHandler(db, cfg))
	}

	// Terraform Binary Mirror endpoints (public, no auth required)
	// Allows clients to discover and download official Terraform/OpenTofu binaries synced by
	// any named mirror config.  The :name segment identifies the mirror configuration.
	tfBinaries := router.Group("/terraform/binaries")
	{
		tfBinaries.GET("", tfBinariesHandler.ListConfigs)
		tfBinaries.GET("/:name/versions", tfBinariesHandler.ListVersions)
		tfBinaries.GET("/:name/versions/latest", tfBinariesHandler.GetLatestVersion)
		tfBinaries.GET("/:name/versions/:version", tfBinariesHandler.GetVersion)
		tfBinaries.GET("/:name/versions/:version/:os/:arch", tfBinariesHandler.DownloadBinary)
	}

	// Initialize admin handlers
	var authHandlers *admin.AuthHandlers
	authHandlers, err = admin.NewAuthHandlers(cfg, db, oidcConfigRepo)
	if err != nil {
		log.Fatalf("Failed to initialize auth handlers: %v", err)
	}

	// Load OIDC configuration from database if available (setup wizard stores config in DB).
	// This takes precedence over static config file settings and allows OIDC to work
	// without requiring config.yaml to have OIDC settings pre-configured.
	if activeOIDCCfg, oidcErr := oidcConfigRepo.GetActiveOIDCConfig(context.Background()); oidcErr == nil && activeOIDCCfg != nil {
		// Decrypt the client secret
		clientSecret, decErr := tokenCipher.Open(activeOIDCCfg.ClientSecretEncrypted)
		if decErr != nil {
			slog.Error("Failed to decrypt OIDC client secret from database", "error", decErr)
		} else {
			liveCfg := &config.OIDCConfig{
				Enabled:      true,
				IssuerURL:    activeOIDCCfg.IssuerURL,
				ClientID:     activeOIDCCfg.ClientID,
				ClientSecret: clientSecret,
				RedirectURL:  activeOIDCCfg.RedirectURL,
				Scopes:       activeOIDCCfg.GetScopes(),
			}
			provider, provErr := oidc.NewOIDCProvider(liveCfg)
			if provErr != nil {
				slog.Error("Failed to initialize OIDC provider from database config", "error", provErr, "issuer", activeOIDCCfg.IssuerURL)
			} else {
				authHandlers.SetOIDCProvider(provider)
				slog.Info("OIDC provider loaded from database configuration", "issuer", activeOIDCCfg.IssuerURL)
			}
		}
	}

	apiKeyHandlers := admin.NewAPIKeyHandlers(cfg, db)
	userHandlers := admin.NewUserHandlers(cfg, db)
	orgHandlers := admin.NewOrganizationHandlers(cfg, db)
	statsHandlers := admin.NewStatsHandler(sqlxDB)
	mirrorHandlers := admin.NewMirrorHandler(mirrorRepo, orgRepo)
	mirrorHandlers.SetSyncJob(mirrorSyncJob) // Connect sync job for manual triggers

	// Initialize Terraform binary mirror admin handler
	tfMirrorAdminHandler := admin.NewTerraformMirrorHandler(tfMirrorRepo)
	tfMirrorAdminHandler.SetSyncJob(tfMirrorSyncJob)
	providerAdminHandlers := admin.NewProviderAdminHandlers(db, storageBackend, cfg)
	moduleAdminHandlers := admin.NewModuleAdminHandlers(db, storageBackend, cfg)

	// Initialize RBAC handlers
	rbacRepo := repositories.NewRBACRepository(sqlxDB)
	rbacHandlers := admin.NewRBACHandlers(rbacRepo)

	// Initialize SCM publisher service (needed by scmLinkingHandler)
	scmPublisher := services.NewSCMPublisher(scmRepo, moduleRepo, storageBackend, tokenCipher)

	// Initialize SCM handlers with the already-created repositories and token cipher
	scmProviderHandlers := admin.NewSCMProviderHandlers(cfg, scmRepo, orgRepo, tokenCipher)
	scmOAuthHandlers := admin.NewSCMOAuthHandlers(cfg, scmRepo, userRepo, tokenCipher)
	scmLinkingHandler := modules.NewSCMLinkingHandler(scmRepo, moduleRepo, tokenCipher, cfg.Server.BaseURL, scmPublisher)

	// Initialize storage configuration handlers
	storageHandlers := admin.NewStorageHandlers(cfg, storageConfigRepo, tokenCipher)

	// Initialize OIDC admin configuration handlers
	oidcAdminHandlers := admin.NewOIDCConfigAdminHandlers(oidcConfigRepo)

	// Initialize setup wizard handlers
	setupHandlers := setup.NewHandlers(
		cfg, tokenCipher, oidcConfigRepo, storageConfigRepo, userRepo, orgRepo, authHandlers,
	)

	// Initialize SCM webhook handler
	scmWebhookHandler := webhooks.NewSCMWebhookHandler(scmRepo, scmPublisher)

	// Initialize rate limiters
	authRateLimiter := middleware.NewRateLimiter(middleware.AuthRateLimitConfig())
	generalRateLimiter := middleware.NewRateLimiter(middleware.DefaultRateLimitConfig())
	uploadRateLimiter := middleware.NewRateLimiter(middleware.UploadRateLimitConfig())

	// Admin API endpoints
	apiV1 := router.Group("/api/v1")
	{
		// Enhanced setup status endpoint (public, no auth required)
		// Returns OIDC, storage, and admin configuration status
		apiV1.GET("/setup/status", setupHandlers.GetSetupStatus)

		// Setup wizard endpoints (setup token auth, rate limited)
		// These endpoints are available only during initial setup and are permanently
		// disabled once setup is completed.
		setupGroup := apiV1.Group("/setup")
		setupGroup.Use(middleware.SetupTokenMiddleware(oidcConfigRepo))
		{
			setupGroup.POST("/validate-token", setupHandlers.ValidateToken)
			setupGroup.POST("/oidc/test", setupHandlers.TestOIDCConfig)
			setupGroup.POST("/oidc", setupHandlers.SaveOIDCConfig)
			setupGroup.POST("/storage/test", setupHandlers.TestStorageConfig)
			setupGroup.POST("/storage", setupHandlers.SaveStorageConfig)
			setupGroup.POST("/admin", setupHandlers.ConfigureAdmin)
			setupGroup.POST("/complete", setupHandlers.CompleteSetup)
		}

		// Public authentication endpoints (no auth required, but rate limited)
		authGroup := apiV1.Group("/auth")
		authGroup.Use(middleware.RateLimitMiddleware(authRateLimiter))
		{
			authGroup.GET("/login", authHandlers.LoginHandler())
			authGroup.GET("/callback", authHandlers.CallbackHandler())
			authGroup.GET("/logout", authHandlers.LogoutHandler())
		}

		// Public search endpoints (no auth required, but rate limited)
		// These allow public discovery of modules and providers without authentication
		publicGroup := apiV1.Group("")
		publicGroup.Use(middleware.RateLimitMiddleware(generalRateLimiter))
		{
			publicGroup.GET("/modules/search", modules.SearchHandler(db, cfg))
			publicGroup.GET("/providers/search", providers.SearchHandler(db, cfg))
		}

		// Public detail endpoints — no auth required; optional auth populates user context if a
		// token is present (used by the frontend to conditionally show management actions).
		publicDetailGroup := apiV1.Group("")
		publicDetailGroup.Use(middleware.OptionalAuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo))
		publicDetailGroup.Use(middleware.RateLimitMiddleware(generalRateLimiter))
		{
			publicDetailGroup.GET("/modules/:namespace/:name/:system", moduleAdminHandlers.GetModule)
			publicDetailGroup.GET("/providers/:namespace/:type", providerAdminHandlers.GetProvider)
		}

		// Authenticated-only endpoints
		authenticatedGroup := apiV1.Group("")
		authenticatedGroup.Use(middleware.AuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo))
		authenticatedGroup.Use(middleware.RateLimitMiddleware(generalRateLimiter))
		authenticatedGroup.Use(middleware.AuditMiddleware(auditRepo)) // Audit all authenticated actions
		{
			// Auth endpoints (require auth)
			authenticatedGroup.POST("/auth/refresh", authHandlers.RefreshHandler())
			authenticatedGroup.GET("/auth/me", authHandlers.MeHandler())

			// Stats endpoints (require auth)
			authenticatedGroup.GET("/admin/stats/dashboard", statsHandlers.GetDashboardStats)

			// Modules admin endpoints - require write permissions
			authenticatedGroup.POST("/admin/modules/create",
				middleware.RequireScope(auth.ScopeModulesWrite),
				moduleAdminHandlers.CreateModuleRecord)
			authenticatedGroup.POST("/modules",
				middleware.RateLimitMiddleware(uploadRateLimiter), // Stricter rate limit for uploads
				middleware.RequireScope(auth.ScopeModulesWrite),
				modules.UploadHandler(db, storageBackend, cfg))

			// Providers admin endpoints - require write permissions
			authenticatedGroup.POST("/providers",
				middleware.RateLimitMiddleware(uploadRateLimiter), // Stricter rate limit for uploads
				middleware.RequireScope(auth.ScopeProvidersWrite),
				providers.UploadHandler(db, storageBackend, cfg))
			authenticatedGroup.DELETE("/providers/:namespace/:type",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				providerAdminHandlers.DeleteProvider)
			authenticatedGroup.DELETE("/providers/:namespace/:type/versions/:version",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				providerAdminHandlers.DeleteVersion)
			authenticatedGroup.POST("/providers/:namespace/:type/versions/:version/deprecate",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				providerAdminHandlers.DeprecateVersion)
			authenticatedGroup.DELETE("/providers/:namespace/:type/versions/:version/deprecate",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				providerAdminHandlers.UndeprecateVersion)

			// Modules admin endpoints - delete, deprecate (GET moved to publicDetailGroup above)
			authenticatedGroup.DELETE("/modules/:namespace/:name/:system",
				middleware.RequireScope(auth.ScopeModulesWrite),
				moduleAdminHandlers.DeleteModule)
			authenticatedGroup.DELETE("/modules/:namespace/:name/:system/versions/:version",
				middleware.RequireScope(auth.ScopeModulesWrite),
				moduleAdminHandlers.DeleteVersion)
			authenticatedGroup.POST("/modules/:namespace/:name/:system/versions/:version/deprecate",
				middleware.RequireScope(auth.ScopeModulesWrite),
				moduleAdminHandlers.DeprecateVersion)
			authenticatedGroup.DELETE("/modules/:namespace/:name/:system/versions/:version/deprecate",
				middleware.RequireScope(auth.ScopeModulesWrite),
				moduleAdminHandlers.UndeprecateVersion)

			// API Keys management - self-service for own keys
			// Users can manage their own API keys without api_keys:manage scope
			// The handlers verify ownership; api_keys:manage is only needed for managing others' keys
			apiKeysGroup := authenticatedGroup.Group("/apikeys")
			{
				apiKeysGroup.GET("", apiKeyHandlers.ListAPIKeysHandler())
				apiKeysGroup.POST("", apiKeyHandlers.CreateAPIKeyHandler())
				apiKeysGroup.GET("/:id", apiKeyHandlers.GetAPIKeyHandler())
				apiKeysGroup.PUT("/:id", apiKeyHandlers.UpdateAPIKeyHandler())
				apiKeysGroup.DELETE("/:id", apiKeyHandlers.DeleteAPIKeyHandler())
				apiKeysGroup.POST("/:id/rotate", apiKeyHandlers.RotateAPIKeyHandler())
			}

			// Self-service user endpoints (any authenticated user)
			// These endpoints allow users to access their own data without special scopes
			authenticatedGroup.GET("/users/me/memberships", userHandlers.GetCurrentUserMembershipsHandler())

			// Users management (requires users:read scope for viewing others)
			usersGroup := authenticatedGroup.Group("/users")
			usersGroup.Use(middleware.RequireScope(auth.ScopeUsersRead))
			{
				usersGroup.GET("", userHandlers.ListUsersHandler())
				usersGroup.GET("/search", userHandlers.SearchUsersHandler())
				usersGroup.GET("/:id", userHandlers.GetUserHandler())
				usersGroup.GET("/:id/memberships", userHandlers.GetUserMembershipsHandler())
			}

			usersWriteGroup := authenticatedGroup.Group("/users")
			usersWriteGroup.Use(middleware.RequireScope(auth.ScopeUsersWrite))
			{
				usersWriteGroup.POST("", userHandlers.CreateUserHandler())
				usersWriteGroup.PUT("/:id", userHandlers.UpdateUserHandler())
				usersWriteGroup.DELETE("/:id", userHandlers.DeleteUserHandler())
			}

			// Organizations management
			orgsGroup := authenticatedGroup.Group("/organizations")
			{
				// Read operations require organizations:read
				orgsGroup.GET("", middleware.RequireScope(auth.ScopeOrganizationsRead), orgHandlers.ListOrganizationsHandler())
				orgsGroup.GET("/search", middleware.RequireScope(auth.ScopeOrganizationsRead), orgHandlers.SearchOrganizationsHandler())
				orgsGroup.GET("/:id", middleware.RequireScope(auth.ScopeOrganizationsRead), orgHandlers.GetOrganizationHandler())
				orgsGroup.GET("/:id/members", middleware.RequireScope(auth.ScopeOrganizationsRead), orgHandlers.ListMembersHandler())

				// Create/update/delete require organizations:write
				orgsGroup.POST("", middleware.RequireScope(auth.ScopeOrganizationsWrite), orgHandlers.CreateOrganizationHandler())
				orgsGroup.PUT("/:id", middleware.RequireScope(auth.ScopeOrganizationsWrite), orgHandlers.UpdateOrganizationHandler())
				orgsGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeOrganizationsWrite), orgHandlers.DeleteOrganizationHandler())

				// Member management requires organizations:write
				orgsGroup.POST("/:id/members", middleware.RequireScope(auth.ScopeOrganizationsWrite), orgHandlers.AddMemberHandler())
				orgsGroup.PUT("/:id/members/:user_id", middleware.RequireScope(auth.ScopeOrganizationsWrite), orgHandlers.UpdateMemberHandler())
				orgsGroup.DELETE("/:id/members/:user_id", middleware.RequireScope(auth.ScopeOrganizationsWrite), orgHandlers.RemoveMemberHandler())
			}

			// SCM Provider management
			scmProvidersGroup := authenticatedGroup.Group("/scm-providers")
			{
				// Read operations require scm:read
				scmProvidersGroup.GET("", middleware.RequireScope(auth.ScopeSCMRead), scmProviderHandlers.ListProviders)
				scmProvidersGroup.GET("/:id", middleware.RequireScope(auth.ScopeSCMRead), scmProviderHandlers.GetProvider)

				// Management operations require scm:manage
				scmProvidersGroup.POST("", middleware.RequireScope(auth.ScopeSCMManage), scmProviderHandlers.CreateProvider)
				scmProvidersGroup.PUT("/:id", middleware.RequireScope(auth.ScopeSCMManage), scmProviderHandlers.UpdateProvider)
				scmProvidersGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeSCMManage), scmProviderHandlers.DeleteProvider)

				// OAuth flow endpoints require scm:manage
				scmProvidersGroup.GET("/:id/oauth/authorize", middleware.RequireScope(auth.ScopeSCMManage), scmOAuthHandlers.InitiateOAuth)
				scmProvidersGroup.GET("/:id/oauth/token", middleware.RequireScope(auth.ScopeSCMRead), scmOAuthHandlers.GetTokenStatus)
				scmProvidersGroup.DELETE("/:id/oauth/token", middleware.RequireScope(auth.ScopeSCMManage), scmOAuthHandlers.RevokeOAuth)
				scmProvidersGroup.POST("/:id/oauth/refresh", middleware.RequireScope(auth.ScopeSCMManage), scmOAuthHandlers.RefreshToken)

				// PAT-based auth (e.g., Bitbucket Data Center)
				scmProvidersGroup.POST("/:id/token", middleware.RequireScope(auth.ScopeSCMManage), scmOAuthHandlers.SavePATToken)

				// Repository listing - requires scm:read
				scmProvidersGroup.GET("/:id/repositories", middleware.RequireScope(auth.ScopeSCMRead), scmOAuthHandlers.ListRepositories)
				scmProvidersGroup.GET("/:id/repositories/:owner/:repo/tags", middleware.RequireScope(auth.ScopeSCMRead), scmOAuthHandlers.ListRepositoryTags)
				scmProvidersGroup.GET("/:id/repositories/:owner/:repo/branches", middleware.RequireScope(auth.ScopeSCMRead), scmOAuthHandlers.ListRepositoryBranches)
			}

			// SCM OAuth callback (public endpoint, no auth required)
			apiV1.GET("/scm-providers/:id/oauth/callback", scmOAuthHandlers.HandleOAuthCallback)

			// Module SCM linking endpoints
			moduleSCMGroup := authenticatedGroup.Group("/admin/modules/:id/scm")
			moduleSCMGroup.Use(middleware.RequireScope(auth.ScopeModulesWrite))
			{
				moduleSCMGroup.POST("", scmLinkingHandler.LinkModuleToSCM)
				moduleSCMGroup.GET("", scmLinkingHandler.GetModuleSCMInfo)
				moduleSCMGroup.PUT("", scmLinkingHandler.UpdateSCMLink)
				moduleSCMGroup.DELETE("", scmLinkingHandler.UnlinkModuleFromSCM)
				moduleSCMGroup.POST("/sync", scmLinkingHandler.TriggerManualSync)
				moduleSCMGroup.GET("/events", scmLinkingHandler.GetWebhookEvents)
			}

			// Mirror management endpoints with granular RBAC
			// Read operations require mirrors:read scope
			// Management operations require mirrors:manage scope
			mirrorsGroup := authenticatedGroup.Group("/admin/mirrors")
			{
				// Read operations - require mirrors:read (or mirrors:manage or admin)
				mirrorsGroup.GET("", middleware.RequireScope(auth.ScopeMirrorsRead), mirrorHandlers.ListMirrorConfigs)
				mirrorsGroup.GET("/:id", middleware.RequireScope(auth.ScopeMirrorsRead), mirrorHandlers.GetMirrorConfig)
				mirrorsGroup.GET("/:id/status", middleware.RequireScope(auth.ScopeMirrorsRead), mirrorHandlers.GetMirrorStatus)

				// Management operations - require mirrors:manage (or admin)
				mirrorsGroup.POST("", middleware.RequireScope(auth.ScopeMirrorsManage), mirrorHandlers.CreateMirrorConfig)
				mirrorsGroup.PUT("/:id", middleware.RequireScope(auth.ScopeMirrorsManage), mirrorHandlers.UpdateMirrorConfig)
				mirrorsGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeMirrorsManage), mirrorHandlers.DeleteMirrorConfig)
				mirrorsGroup.POST("/:id/sync", middleware.RequireScope(auth.ScopeMirrorsManage), mirrorHandlers.TriggerSync)
			}

			// Terraform Binary Mirror admin endpoints (multi-config)
			// Read operations require mirrors:read scope; management requires mirrors:manage
			tfMirrorGroup := authenticatedGroup.Group("/admin/terraform-mirrors")
			{
				// Config CRUD
				tfMirrorGroup.GET("", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.ListConfigs)
				tfMirrorGroup.POST("", middleware.RequireScope(auth.ScopeMirrorsManage), tfMirrorAdminHandler.CreateConfig)
				tfMirrorGroup.GET("/:id", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.GetConfig)
				tfMirrorGroup.GET("/:id/status", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.GetStatus)
				tfMirrorGroup.PUT("/:id", middleware.RequireScope(auth.ScopeMirrorsManage), tfMirrorAdminHandler.UpdateConfig)
				tfMirrorGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeMirrorsManage), tfMirrorAdminHandler.DeleteConfig)
				// Sync trigger
				tfMirrorGroup.POST("/:id/sync", middleware.RequireScope(auth.ScopeMirrorsManage), tfMirrorAdminHandler.TriggerSync)
				// Versions
				tfMirrorGroup.GET("/:id/versions", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.ListVersions)
				tfMirrorGroup.GET("/:id/versions/:version", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.GetVersion)
				tfMirrorGroup.DELETE("/:id/versions/:version", middleware.RequireScope(auth.ScopeMirrorsManage), tfMirrorAdminHandler.DeleteVersion)
				tfMirrorGroup.GET("/:id/versions/:version/platforms", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.ListPlatforms)
				// Sync history
				tfMirrorGroup.GET("/:id/history", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.GetSyncHistory)
			}

			// Role Templates management
			roleTemplatesGroup := authenticatedGroup.Group("/admin/role-templates")
			{
				roleTemplatesGroup.GET("", rbacHandlers.ListRoleTemplates)
				roleTemplatesGroup.GET("/:id", rbacHandlers.GetRoleTemplate)
				roleTemplatesGroup.POST("", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.CreateRoleTemplate)
				roleTemplatesGroup.PUT("/:id", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.UpdateRoleTemplate)
				roleTemplatesGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.DeleteRoleTemplate)
			}

			// Mirror Approval Requests
			approvalsGroup := authenticatedGroup.Group("/admin/approvals")
			{
				approvalsGroup.GET("", middleware.RequireScope(auth.ScopeMirrorsRead), rbacHandlers.ListApprovalRequests)
				approvalsGroup.GET("/:id", middleware.RequireScope(auth.ScopeMirrorsRead), rbacHandlers.GetApprovalRequest)
				approvalsGroup.POST("", middleware.RequireScope(auth.ScopeMirrorsManage), rbacHandlers.CreateApprovalRequest)
				approvalsGroup.PUT("/:id/review", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.ReviewApproval)
			}

			// Mirror Policies
			policiesGroup := authenticatedGroup.Group("/admin/policies")
			{
				policiesGroup.GET("", middleware.RequireScope(auth.ScopeMirrorsRead), rbacHandlers.ListMirrorPolicies)
				policiesGroup.GET("/:id", middleware.RequireScope(auth.ScopeMirrorsRead), rbacHandlers.GetMirrorPolicy)
				policiesGroup.POST("", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.CreateMirrorPolicy)
				policiesGroup.PUT("/:id", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.UpdateMirrorPolicy)
				policiesGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.DeleteMirrorPolicy)
				policiesGroup.POST("/evaluate", middleware.RequireScope(auth.ScopeMirrorsRead), rbacHandlers.EvaluatePolicy)
			}

			// Storage Configuration management (requires admin scope)
			storageGroup := authenticatedGroup.Group("/storage")
			storageGroup.Use(middleware.RequireScope(auth.ScopeAdmin))
			{
				storageGroup.GET("/config", storageHandlers.GetActiveStorageConfig)
				storageGroup.GET("/configs", storageHandlers.ListStorageConfigs)
				storageGroup.GET("/configs/:id", storageHandlers.GetStorageConfig)
				storageGroup.POST("/configs", storageHandlers.CreateStorageConfig)
				storageGroup.PUT("/configs/:id", storageHandlers.UpdateStorageConfig)
				storageGroup.DELETE("/configs/:id", storageHandlers.DeleteStorageConfig)
				storageGroup.POST("/configs/:id/activate", storageHandlers.ActivateStorageConfig)
				storageGroup.POST("/configs/test", storageHandlers.TestStorageConfig)
			}

			// OIDC admin configuration management (requires admin scope)
			oidcAdminGroup := authenticatedGroup.Group("/admin/oidc")
			oidcAdminGroup.Use(middleware.RequireScope(auth.ScopeAdmin))
			{
				oidcAdminGroup.GET("/config", oidcAdminHandlers.GetActiveOIDCConfig)
				oidcAdminGroup.PUT("/group-mapping", oidcAdminHandlers.UpdateGroupMapping)
			}
		}

		// Development-only endpoints (guarded by DevModeMiddleware)
		devGroup := apiV1.Group("/dev")
		devGroup.Use(admin.DevModeMiddleware())
		{
			devHandlers := admin.NewDevHandlers(cfg, db)
			// Unauthenticated dev endpoints (dev-mode-gated only)
			devGroup.GET("/status", devHandlers.DevStatusHandler())
			devGroup.POST("/login", devHandlers.DevLoginHandler())

			// Impersonation endpoints (require auth + admin scope)
			devGroup.Use(middleware.AuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo))
			devGroup.GET("/users", devHandlers.ListUsersForImpersonationHandler())
			devGroup.POST("/impersonate/:user_id", devHandlers.ImpersonateUserHandler())
		}
	}

	// Webhook endpoints (public, authentication via signature validation)
	router.POST("/webhooks/scm/:module_source_repo_id/:secret", scmWebhookHandler.HandleWebhook)

	bg := &BackgroundServices{
		mirrorSyncJob:   mirrorSyncJob,
		tfMirrorSyncJob: tfMirrorSyncJob,
		expiryNotifier:  expiryNotifier,
		rateLimiters:    []*middleware.RateLimiter{authRateLimiter, generalRateLimiter, uploadRateLimiter},
	}

	return router, bg
}

// @Summary      Health check
// @Description  Returns the health status of the service, including database connectivity.
// @Tags         System
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "status: healthy, time: RFC3339 timestamp"
// @Failure      503  {object}  map[string]interface{}  "status: unhealthy, error: database connection failed"
// @Router       /health [get]
// healthCheckHandler returns the health status of the service
func healthCheckHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check database connection
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
				"error":  "database connection failed",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// @Summary      Readiness check
// @Description  Returns whether the service is ready to accept traffic. Checks database connectivity.
// @Tags         System
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "ready: true, time: RFC3339 timestamp"
// @Failure      503  {object}  map[string]interface{}  "ready: false, error: database not ready"
// @Router       /ready [get]
// readinessHandler returns the readiness status of the service.
// Unlike the liveness probe (/health), this also checks the storage backend so
// that a Kubernetes readiness gate fails when uploads/downloads would error.
func readinessHandler(db *sql.DB, storageBackend storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		checks := gin.H{}

		// Check database connection
		if err := db.Ping(); err != nil {
			checks["database"] = "unhealthy"
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"ready":  false,
				"checks": checks,
				"error":  "database not ready",
			})
			return
		}
		checks["database"] = "healthy"

		// Check storage backend — probe with a known-absent sentinel path.
		// Exists() exercises authentication and network connectivity without
		// creating any state.
		if _, err := storageBackend.Exists(c.Request.Context(), ".readiness-probe"); err != nil {
			checks["storage"] = "unhealthy"
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"ready":  false,
				"checks": checks,
				"error":  "storage backend not ready",
			})
			return
		}
		checks["storage"] = "healthy"

		c.JSON(http.StatusOK, gin.H{
			"ready":  true,
			"checks": checks,
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// @Summary      Terraform service discovery
// @Description  Implements the Terraform service discovery protocol. Returns the base URLs for the Module Registry and Provider Registry endpoints.
// @Tags         System
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "modules.v1: URL, providers.v1: URL"
// @Router       /.well-known/terraform.json [get]
// serviceDiscoveryHandler implements Terraform service discovery
func serviceDiscoveryHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"modules.v1":   cfg.Server.BaseURL + "/v1/modules/",
			"providers.v1": cfg.Server.BaseURL + "/v1/providers/",
		})
	}
}

// @Summary      API version
// @Description  Returns the current API version and supported protocol versions.
// @Tags         System
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "version, api_version, protocols: {modules, providers, mirror}"
// @Router       /version [get]
// versionHandler returns the API version
func versionHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":     "0.1.0",
			"api_version": "v1",
			"protocols": gin.H{
				"modules":   "v1",
				"providers": "v1",
				"mirror":    "v1",
			},
		})
	}
}

// LoggerMiddleware provides structured logging
func LoggerMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)

		// Log the request
		if cfg.Logging.Format == "json" {
			logJSON(c, latency, path, query)
		} else {
			logText(c, latency, path, query)
		}
	}
}

// logJSON logs a request as a JSON-structured slog record.
func logJSON(c *gin.Context, latency time.Duration, path, query string) {
	requestID, _ := c.Get(middleware.RequestIDKey)
	slog.LogAttrs(
		c.Request.Context(),
		slog.LevelInfo,
		"http request",
		slog.String("method", c.Request.Method),
		slog.String("path", path),
		slog.String("query", query),
		slog.Int("status", c.Writer.Status()),
		slog.Int("size", c.Writer.Size()),
		slog.Duration("latency", latency),
		slog.String("ip", c.ClientIP()),
		slog.String("request_id", fmt.Sprintf("%v", requestID)),
		slog.String("user_agent", c.Request.UserAgent()),
	)
}

// logText logs a request as a human-readable slog text record.
func logText(c *gin.Context, latency time.Duration, path, query string) {
	// reuse the same structured output; slog will emit text format when the global
	// handler is a TextHandler (configured in telemetry.SetupLogger).
	logJSON(c, latency, path, query)
}

// CORSMiddleware handles CORS
func CORSMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range cfg.Security.CORS.AllowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			if origin == "" {
				c.Header("Access-Control-Allow-Origin", "*")
			} else {
				c.Header("Access-Control-Allow-Origin", origin)
			}
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With")
			c.Header("Access-Control-Max-Age", "3600")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
