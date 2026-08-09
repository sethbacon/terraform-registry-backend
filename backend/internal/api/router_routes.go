// router_routes.go holds the HTTP route-registration phases extracted from
// NewRouter (issue #565 finding [39]): registerPublicRoutes covers the
// unauthenticated Terraform-protocol/OCI/Swagger surface, and
// registerAPIV1Routes covers the /api/v1, /scim/v2, and webhook routes.
// Each takes a small dependency struct built from NewRouter's locals; the
// route-registration bodies themselves were moved verbatim (not rewritten),
// with each dependency struct field re-bound to a local of the same name at
// the top of the function so the body needed no further edits.
package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/sethbacon/terraform-suite-identity/identity/suite"
	"github.com/terraform-registry/terraform-registry/docs"
	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/api/advisories"
	"github.com/terraform-registry/terraform-registry/internal/api/mirror"
	"github.com/terraform-registry/terraform-registry/internal/api/modules"
	"github.com/terraform-registry/terraform-registry/internal/api/oci"
	"github.com/terraform-registry/terraform-registry/internal/api/providers"
	"github.com/terraform-registry/terraform-registry/internal/api/scim"
	"github.com/terraform-registry/terraform-registry/internal/api/setup"
	terraform_binaries "github.com/terraform-registry/terraform-registry/internal/api/terraform_binaries"
	"github.com/terraform-registry/terraform-registry/internal/api/uitheme"
	"github.com/terraform-registry/terraform-registry/internal/api/webhooks"
	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/credlifecycle"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
	"github.com/terraform-registry/terraform-registry/internal/notify"
	"github.com/terraform-registry/terraform-registry/internal/policy"
	"github.com/terraform-registry/terraform-registry/internal/services"
	"github.com/terraform-registry/terraform-registry/internal/storage"
)

// publicRouteDeps holds every dependency registerPublicRoutes needs.
type publicRouteDeps struct {
	cfg                     *config.Config
	db                      *sql.DB
	storageBackend          storage.Storage
	ociHandler              *oci.Handler
	userRepo                *repositories.UserRepository
	apiKeyRepo              *repositories.APIKeyRepository
	orgRepo                 *repositories.OrganizationRepository
	tokenRepo               *repositories.TokenRepository
	userTokenRevocationRepo *repositories.UserTokenRevocationRepository
	auditRepo               *repositories.AuditRepository
	pullThroughSvc          *services.PullThroughService
	tfBinariesHandler       *terraform_binaries.Handler
	// protocolRateLimiter bounds anonymous request volume against the
	// Terraform-protocol/OCI/mirror handlers (issue #743). Nil when rate
	// limiting is disabled, which RateLimitMiddleware passes through.
	protocolRateLimiter middleware.RateLimiterBackend
}

// registerPublicRoutes wires the unauthenticated Terraform-protocol/OCI/Swagger
// route table onto router.
// coverage:skip:integration-only — registers the Terraform-protocol/OCI/Swagger route table; tested via E2E
func registerPublicRoutes(router *gin.Engine, d *publicRouteDeps) {
	cfg := d.cfg
	db := d.db
	storageBackend := d.storageBackend
	ociHandler := d.ociHandler
	userRepo := d.userRepo
	apiKeyRepo := d.apiKeyRepo
	orgRepo := d.orgRepo
	tokenRepo := d.tokenRepo
	userTokenRevocationRepo := d.userTokenRevocationRepo
	auditRepo := d.auditRepo
	pullThroughSvc := d.pullThroughSvc
	tfBinariesHandler := d.tfBinariesHandler

	// protocolLimit bounds anonymous request volume across this whole route
	// table (issue #743). Every family here was previously unlimited: module
	// and provider version listing/download, the network mirror (whose
	// pull-through path issues upstream fetches and DB writes on a cache
	// miss), OCI GetBlob (streams whole archives through io.Copy), and the
	// binary mirror when BinaryMirror.Auth is the default "none". These are
	// the highest-volume, fully unauthenticated, internet-reachable handlers
	// in the service, and each one does DB lookups and storage round trips.
	//
	// Applied to everything below EXCEPT /health and /ready. Those two are
	// deliberately unlimited: they are liveness/readiness probes, kubelet
	// probes for every pod on a node share that node's source address, and a
	// 429 on /ready pulls a healthy pod out of service -- a rate limiter
	// causing the outage it exists to prevent. RateLimitMiddleware passes
	// through when the backend is nil (rate limiting disabled).
	protocolLimit := middleware.RateLimitMiddleware(d.protocolRateLimiter)

	// Health check endpoint
	router.GET("/health", healthCheckHandler(db))

	// Readiness check endpoint (includes storage backend probe)
	router.GET("/ready", readinessHandler(db, storageBackend))

	// Service discovery endpoint (Terraform protocol)
	router.GET("/.well-known/terraform.json", protocolLimit, serviceDiscoveryHandler(cfg))

	// OCI Distribution Spec v1.1 — module archive pull endpoint
	v2Group := router.Group("/v2")
	v2Group.Use(protocolLimit)
	{
		v2Group.GET("/", ociHandler.Ping)
		v2Group.HEAD("/:namespace/:name/:system/manifests/:reference", ociHandler.HeadManifest)
		v2Group.GET("/:namespace/:name/:system/manifests/:reference", ociHandler.GetManifest)
		v2Group.HEAD("/:namespace/:name/:system/blobs/:digest", ociHandler.HeadBlob)
		v2Group.GET("/:namespace/:name/:system/blobs/:digest", ociHandler.GetBlob)
		v2Group.PUT("/:namespace/:name/:system/manifests/:reference", ociHandler.PutManifest)
	}

	// API version
	router.GET("/version", protocolLimit, versionHandler(cfg))

	// Swagger UI - served from embedded static assets (air-gap safe)
	swaggerUIFS, _ := fs.Sub(docs.SwaggerUIAssets, "swagger-ui")
	// StaticFS registers GET and HEAD under /api-docs/static/*filepath. It takes
	// no per-route middleware, so the limiter is applied via a group -- found by
	// the route-table enumeration in public_routes_ratelimit_test.go, which sees
	// routes that reading the registration code does not.
	swaggerStatic := router.Group("/api-docs/static")
	swaggerStatic.Use(protocolLimit)
	swaggerStatic.StaticFS("", http.FS(swaggerUIFS))

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

		// Set a nonce-based Content Security Policy — all assets are self-hosted
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Security-Policy", fmt.Sprintf(
			"default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'nonce-%s'; img-src 'self' data:; font-src 'self'; connect-src 'self'",
			nonce, nonce,
		))

		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
	<head>
		<title>Swagger UI</title>
		<meta charset="utf-8"/>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<link rel="stylesheet" href="/api-docs/static/swagger-ui.css">
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
			body {
				font-family: sans-serif;
				color: #fafafa;
			}
		</style>
	</head>

	<body>
		<div id="swagger-ui"></div>

		<script src="/api-docs/static/swagger-ui-bundle.js"></script>
		<script src="/api-docs/static/swagger-ui-standalone-preset.js"></script>
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
				docExpansion: "list",
				tagsSorter: "alpha"
			})
			window.ui = ui
		}
	</script>
	</body>
</html>`, nonce, nonce)

		c.Data(200, "text/html; charset=utf-8", []byte(html))
	}

	// Register both exact and trailing-slash routes for Swagger UI
	router.GET("/api-docs/index.html", protocolLimit, serveSwaggerUI)
	router.GET("/api-docs/", protocolLimit, serveSwaggerUI)
	// Redirect /api-docs -> /api-docs/
	router.GET("/api-docs", protocolLimit, func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/api-docs/")
	})

	// Raw Swagger JSON endpoint - serve embedded spec with runtime metadata.
	// CORS is governed by the globally-applied CORSMiddleware like every
	// other route; do not set Access-Control-Allow-Origin here (issue #684).
	router.GET("/swagger.json", protocolLimit, func(c *gin.Context) {
		c.Header("Content-Type", "application/json")

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

	// Raw OpenAPI 3 JSON — same spec as /swagger.json converted to OpenAPI 3
	// at build time via swagger2openapi. Served without runtime metadata
	// injection because downstream consumers (frontend typegen, provider
	// oapi-codegen) only care about the route and schema surface, not
	// terms-of-service / license fields. CORS is governed by the
	// globally-applied CORSMiddleware like every other route (issue #684).
	router.GET("/openapi3.json", protocolLimit, func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.Data(http.StatusOK, "application/json", docs.OpenAPI3JSON)
	})

	// Module Registry endpoints (v1) - Terraform Protocol
	// These are public endpoints that support optional authentication
	v1Modules := router.Group("/v1/modules")
	v1Modules.Use(protocolLimit)
	v1Modules.Use(middleware.OptionalAuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo, tokenRepo, userTokenRevocationRepo))
	{
		v1Modules.GET("/:namespace/:name/:system/versions", modules.ListVersionsHandler(db, cfg))
		v1Modules.GET("/:namespace/:name/:system/:version/download", modules.DownloadHandler(db, storageBackend, cfg, auditRepo))
	}

	// File serving endpoint for local storage with ServeDirectly enabled
	router.GET("/v1/files/*filepath", protocolLimit, modules.ServeFileHandler(storageBackend, cfg, db, auditRepo))

	// Provider Registry endpoints (v1)
	// These are for the standard Provider Registry Protocol
	v1Providers := router.Group("/v1/providers")
	v1Providers.Use(protocolLimit)
	v1Providers.Use(middleware.OptionalAuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo, tokenRepo, userTokenRevocationRepo))
	{
		v1Providers.GET("/:namespace/:type/versions", providers.ListVersionsHandler(db, cfg))
		v1Providers.GET("/:namespace/:type/:version/download/:os/:arch", providers.DownloadHandler(db, storageBackend, cfg, auditRepo))
	}

	// Network Mirror endpoints (separate from Provider Registry to avoid routing conflicts)
	// These endpoints include the hostname of the origin registry as per the Network Mirror Protocol
	// They use a different path structure: /terraform/providers/:hostname/:namespace/:type/...
	v1Mirror := router.Group("/terraform/providers")
	v1Mirror.Use(protocolLimit)
	{
		v1Mirror.GET("/:hostname/:namespace/:type/index.json", mirror.IndexHandler(db, cfg, pullThroughSvc))
		v1Mirror.GET("/:hostname/:namespace/:type/:versionfile", mirror.PlatformIndexHandler(db, cfg, auditRepo, pullThroughSvc))
	}

	// Terraform Binary Mirror endpoints (public by default, protected when auth mode is configured)
	// Allows clients to discover and download official Terraform/OpenTofu binaries synced by
	// any named mirror config.  The :name segment identifies the mirror configuration.
	tfBinaries := router.Group("/terraform/binaries")
	tfBinaries.Use(protocolLimit)
	tfBinaries.Use(middleware.BinaryMirrorAuthMiddleware(cfg.BinaryMirror))
	{
		tfBinaries.GET("", tfBinariesHandler.ListConfigs)
		tfBinaries.GET("/:name/versions", tfBinariesHandler.ListVersions)
		tfBinaries.GET("/:name/versions/latest", tfBinariesHandler.GetLatestVersion)
		tfBinaries.GET("/:name/versions/:version", tfBinariesHandler.GetVersion)
		tfBinaries.GET("/:name/versions/:version/:os/:arch", tfBinariesHandler.DownloadBinary)
	}
}

// apiV1RouteDeps holds every dependency registerAPIV1Routes needs.
type apiV1RouteDeps struct {
	cfg                     *config.Config
	db                      *sql.DB
	storageBackend          storage.Storage
	sqlxDB                  *sqlx.DB
	oidcConfigRepo          *repositories.OIDCConfigRepository
	setupHandlers           *setup.Handlers
	authRateLimiter         middleware.RateLimiterBackend
	generalRateLimiter      middleware.RateLimiterBackend
	uploadRateLimiter       middleware.RateLimiterBackend
	orgRateLimiter          middleware.RateLimiterBackend
	principalOverrides      *middleware.PrincipalOverrideLimiters
	authHandlers            *admin.AuthHandlers
	userRepo                *repositories.UserRepository
	apiKeyRepo              *repositories.APIKeyRepository
	orgRepo                 *repositories.OrganizationRepository
	tokenRepo               *repositories.TokenRepository
	userTokenRevocationRepo *repositories.UserTokenRevocationRepository
	// credSweeper invalidates every credential family that snapshots a
	// principal's derived authority when a lifecycle event reduces it
	// (issues #732, #736). Built once in NewRouter because its two halves
	// live on different connections.
	credSweeper                 *credlifecycle.Sweeper
	moduleAdminHandlers         *admin.ModuleAdminHandlers
	providerAdminHandlers       *admin.ProviderAdminHandlers
	auditRepo                   *repositories.AuditRepository
	auditShipper                audit.Shipper
	nsAuthz                     *middleware.NamespaceAuthorizer
	scmRepo                     *repositories.SCMRepository
	mirrorRepo                  *repositories.MirrorRepository
	rbacRepo                    *repositories.RBACRepository
	scanRepo                    *repositories.ModuleScanRepository
	moduleDocsRepo              *repositories.ModuleDocsRepository
	policyEngine                *policy.PolicyEngine
	sbvRepo                     *repositories.ScannerBinaryVersionRepository
	scannerApprovalRepo         *repositories.VersionApprovalRepository
	scannerUpdateJob            *jobs.ScannerUpdateJob
	notificationsHandler        *admin.NotificationsHandler
	notificationChannelHandlers *admin.NotificationChannelHandlers
	notifier                    *notify.Notifier
	apiKeyHandlers              *admin.APIKeyHandlers
	userHandlers                *admin.UserHandlers
	gdprHandlers                *admin.GDPRHandlers
	orgHandlers                 *admin.OrganizationHandlers
	scmProviderHandlers         *admin.SCMProviderHandlers
	scmOAuthHandlers            *admin.SCMOAuthHandlers
	scmLinkingHandler           *modules.SCMLinkingHandler
	mirrorHandlers              *admin.MirrorHandler
	tfMirrorAdminHandler        *admin.TerraformMirrorHandler
	releasesGPGKeysAdminHandler *admin.ReleasesGPGKeysHandler
	rbacHandlers                *admin.RBACHandlers
	versionApprovalHandler      *admin.VersionApprovalHandler
	storageHandlers             *admin.StorageHandlers
	storageConfigRepo           *repositories.StorageConfigRepository
	moduleRepo                  *repositories.ModuleRepository
	providerRepo                *repositories.ProviderRepository
	tokenCipher                 *crypto.TokenCipher
	oidcAdminHandlers           *admin.OIDCConfigAdminHandlers
	auditLogHandlers            *admin.AuditLogHandlers
	policyAdminHandler          *admin.PolicyHandler
	cvePollJob                  *jobs.CVEPollJob
	statsHandlers               *admin.StatsHandler
	scmWebhookHandler           *webhooks.SCMWebhookHandler
	approvalWebhookHandler      *webhooks.ApprovalHandler
	egressGuard                 *httpsafe.Guard
}

// registerAuthenticatedGroupMiddleware wires the middleware stack applied to
// every authenticated API v1 route: auth, CSRF, per-principal and
// per-organization rate limiting, and audit logging. Extracted into its own
// function (rather than inlined in registerAPIV1Routes, which is
// coverage:skip:integration-only and requires the full handler dependency
// graph to construct) specifically so this wiring — in particular, passing
// the real auditShipper and &cfg.Audit into AuditMiddlewareWithShipper rather
// than the pre-#659 hardcoded nils — has a direct regression test
// (TestRegisterAuthenticatedGroupMiddleware_AuditShipsToRealShipper).
func registerAuthenticatedGroupMiddleware(authenticatedGroup *gin.RouterGroup, d *apiV1RouteDeps) {
	authenticatedGroup.Use(middleware.AuthMiddleware(d.cfg, d.userRepo, d.apiKeyRepo, d.orgRepo, d.tokenRepo, d.userTokenRevocationRepo))
	authenticatedGroup.Use(middleware.CSRFMiddleware(d.cfg)) // double-submit cookie CSRF protection + browser-origin Bearer allowlist
	authenticatedGroup.Use(middleware.PrincipalRateLimitMiddleware(d.generalRateLimiter, d.principalOverrides))
	authenticatedGroup.Use(middleware.OrgRateLimitMiddleware(d.generalRateLimiter, d.orgRateLimiter))
	// Audit all authenticated actions. Ships to any configured external
	// destinations and honors cfg.Audit.LogReadOperations/LogFailedRequests
	// (issue #659 — previously always AuditMiddleware(auditRepo), which
	// hardcodes shipper=nil and auditCfg=nil).
	authenticatedGroup.Use(middleware.AuditMiddlewareWithShipper(d.auditRepo, d.auditShipper, &d.cfg.Audit))
}

// registerAPIV1Routes wires the /api/v1, /scim/v2, and webhook route table
// onto router.
// coverage:skip:integration-only — registers the /api/v1, /scim/v2, and webhook route table; tested via E2E
func registerAPIV1Routes(router *gin.Engine, d *apiV1RouteDeps) {
	cfg := d.cfg
	db := d.db
	storageBackend := d.storageBackend
	sqlxDB := d.sqlxDB
	oidcConfigRepo := d.oidcConfigRepo
	setupHandlers := d.setupHandlers
	authRateLimiter := d.authRateLimiter
	generalRateLimiter := d.generalRateLimiter
	uploadRateLimiter := d.uploadRateLimiter
	authHandlers := d.authHandlers
	userRepo := d.userRepo
	apiKeyRepo := d.apiKeyRepo
	orgRepo := d.orgRepo
	tokenRepo := d.tokenRepo
	userTokenRevocationRepo := d.userTokenRevocationRepo
	moduleAdminHandlers := d.moduleAdminHandlers
	providerAdminHandlers := d.providerAdminHandlers
	nsAuthz := d.nsAuthz
	scanRepo := d.scanRepo
	moduleDocsRepo := d.moduleDocsRepo
	policyEngine := d.policyEngine
	sbvRepo := d.sbvRepo
	scannerApprovalRepo := d.scannerApprovalRepo
	scannerUpdateJob := d.scannerUpdateJob
	notificationsHandler := d.notificationsHandler
	notificationChannelHandlers := d.notificationChannelHandlers
	notifier := d.notifier
	apiKeyHandlers := d.apiKeyHandlers
	userHandlers := d.userHandlers
	gdprHandlers := d.gdprHandlers
	orgHandlers := d.orgHandlers
	scmProviderHandlers := d.scmProviderHandlers
	scmOAuthHandlers := d.scmOAuthHandlers
	scmLinkingHandler := d.scmLinkingHandler
	mirrorHandlers := d.mirrorHandlers
	tfMirrorAdminHandler := d.tfMirrorAdminHandler
	releasesGPGKeysAdminHandler := d.releasesGPGKeysAdminHandler
	rbacHandlers := d.rbacHandlers
	versionApprovalHandler := d.versionApprovalHandler
	storageHandlers := d.storageHandlers
	storageConfigRepo := d.storageConfigRepo
	moduleRepo := d.moduleRepo
	providerRepo := d.providerRepo
	tokenCipher := d.tokenCipher
	oidcAdminHandlers := d.oidcAdminHandlers
	auditLogHandlers := d.auditLogHandlers
	policyAdminHandler := d.policyAdminHandler
	cvePollJob := d.cvePollJob
	statsHandlers := d.statsHandlers
	scmWebhookHandler := d.scmWebhookHandler
	approvalWebhookHandler := d.approvalWebhookHandler
	egressGuard := d.egressGuard

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
			setupGroup.POST("/ldap/test", setupHandlers.TestLDAPConfig)
			setupGroup.POST("/ldap", setupHandlers.SaveLDAPConfig)
			setupGroup.POST("/storage/test", setupHandlers.TestStorageConfig)
			setupGroup.POST("/storage", setupHandlers.SaveStorageConfig)
			setupGroup.POST("/admin", setupHandlers.ConfigureAdmin)
			setupGroup.POST("/scanning/test", setupHandlers.TestScanningConfig)
			setupGroup.POST("/scanning", setupHandlers.SaveScanningConfig)
			setupGroup.POST("/scanning/install", setupHandlers.InstallScanner)
			setupGroup.POST("/complete", setupHandlers.CompleteSetup)

			// White-label theme — wizard BrandingStep upserts via setup-token auth.
			// Same handler is also mounted under /admin/ui-theme below for post-setup edits.
			setupUIThemeHandlers := uitheme.NewHandlers(sqlxDB)
			setupGroup.PUT("/ui-theme", setupUIThemeHandlers.PutTheme())
		}

		// Public authentication endpoints (no auth required, but rate limited)
		authGroup := apiV1.Group("/auth")
		authGroup.Use(middleware.RateLimitMiddleware(authRateLimiter))
		{
			authGroup.GET("/login", authHandlers.LoginHandler())
			authGroup.GET("/callback", authHandlers.CallbackHandler())
			// Logout is POST-only. A GET logout sits outside the CSRF check
			// (safe methods are exempt) and the auth cookie rides a cross-site
			// top-level navigation, so a link could force a victim's session to
			// be revoked; there is deliberately no GET route.
			//
			// This group is the PUBLIC one, so it does not inherit
			// registerAuthenticatedGroupMiddleware's CSRFMiddleware — it has to
			// be attached to this route explicitly, otherwise the POST form
			// would be exactly as forgeable as the GET one it replaced.
			//
			// It does not inherit an auth middleware either, and logout is a
			// handler that has to act on the caller's own token: the invariant
			// is that a completed logout leaves the presented JWT unusable, and
			// endSession can only revoke a JTI the middleware chain resolved for
			// it (issue #764). Optional — not required — auth, because a logout
			// with no session, or one whose token already expired, must still
			// clear cookies and answer 200 rather than 401.
			//
			// CSRF runs first, deliberately: it treats an unauthenticated
			// request as cookie-authenticated and so demands the double-submit
			// token unconditionally on this route. Establishing auth_method
			// first would instead route Bearer logouts into CSRFMiddleware's
			// header-JWT branch, loosening a check this route already passes.
			authGroup.POST("/logout",
				middleware.CSRFMiddleware(cfg),
				middleware.OptionalAuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo, tokenRepo, userTokenRevocationRepo),
				authHandlers.LogoutPostHandler())
			authGroup.GET("/providers", authHandlers.ProvidersHandler())

			// SAML endpoints
			authGroup.GET("/saml/metadata", authHandlers.SAMLMetadataHandler())
			authGroup.POST("/saml/acs", authHandlers.SAMLACSHandler())

			// LDAP endpoint
			authGroup.POST("/ldap/login", authHandlers.LDAPLoginHandler())
		}

		// Public search endpoints (no auth required, but rate limited)
		// These allow public discovery of modules and providers without authentication
		var suiteClient *suite.DiscoveryClient
		publicGroup := apiV1.Group("")
		publicGroup.Use(middleware.RateLimitMiddleware(generalRateLimiter))
		{
			publicGroup.GET("/modules/search", modules.SearchHandler(db, cfg))
			publicGroup.GET("/providers/search", providers.SearchHandler(db, cfg))
			// CVE advisory banner endpoint — consumed by the frontend to show active advisories
			advisoryHandlers := advisories.NewHandlers(db)
			publicGroup.GET("/advisories/active", advisoryHandlers.ListActive())

			// White-label UI theme — read endpoint is public so the unauthenticated
			// login page can render branded colors/logo before sign-in.
			uiThemeHandlers := uitheme.NewHandlers(sqlxDB)
			publicGroup.GET("/ui/theme", uiThemeHandlers.GetTheme())

			// Suite runtime discovery (Phase 0)
			publicGroup.GET("/suite/manifest", suiteManifestHandler(cfg))
			publicGroup.GET("/ui/config", uiConfigHandler(cfg, func() *suite.DiscoveryClient { return suiteClient }))
		}
		suiteClient = startSuiteDiscovery(cfg)

		// Public detail endpoints — no auth required; optional auth populates user context if a
		// token is present (used by the frontend to conditionally show management actions).
		publicDetailGroup := apiV1.Group("")
		publicDetailGroup.Use(middleware.OptionalAuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo, tokenRepo, userTokenRevocationRepo))
		publicDetailGroup.Use(middleware.RateLimitMiddleware(generalRateLimiter))
		{
			publicDetailGroup.GET("/modules/:namespace/:name/:system", moduleAdminHandlers.GetModule)
			publicDetailGroup.GET("/modules/:namespace/:name/:system/:version", moduleAdminHandlers.GetModuleVersion)
			publicDetailGroup.GET("/modules/:namespace/:name/:system/versions/:version/docs", modules.GetModuleDocsHandler(db))
			publicDetailGroup.GET("/providers/:namespace/:type", providerAdminHandlers.GetProvider)
			publicDetailGroup.GET("/providers/:namespace/:type/versions/:version/docs", providers.ListProviderDocsHandler(db))
			publicDetailGroup.GET("/providers/:namespace/:type/versions/:version/docs/:category/:slug", providers.GetProviderDocContentHandler(db, cfg))
		}

		// Authenticated-only endpoints
		authenticatedGroup := apiV1.Group("")
		registerAuthenticatedGroupMiddleware(authenticatedGroup, d)
		{
			// Auth endpoints (require auth)
			authenticatedGroup.POST("/auth/refresh", authHandlers.RefreshHandler())
			authenticatedGroup.GET("/auth/me", authHandlers.MeHandler())

			// Suite coupling: "Consumed by" — which sibling-app states use this
			// module. Server-proxied to the sibling (2s timeout, [] on any failure),
			// auth-required so internal state/source names aren't exposed anonymously.
			// Namespaced under /suite to avoid the /modules/:version wildcard.
			authenticatedGroup.GET("/suite/modules/:namespace/:name/:system/consumers",
				moduleConsumersHandler(func() *suite.DiscoveryClient { return suiteClient }, cfg, egressGuard))

			// Stats endpoints (require auth)
			authenticatedGroup.GET("/admin/stats/dashboard", statsHandlers.GetDashboardStats)

			// Modules admin endpoints - require write permissions plus
			// namespace-org authorization (issue #555)
			authenticatedGroup.POST("/admin/modules/create",
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequirePublishAccessFromJSON(auth.ScopeModulesWrite),
				moduleAdminHandlers.CreateModuleRecord)
			// The by-id READ is guarded on the same axis as its PUT sibling
			// (issue #719): GetModuleByIDRecord emits the whole modules row,
			// organization_id included, for any id in any organization, and
			// the repository call carries no organization predicate. Same
			// reasoning as the module-SCM GETs below.
			authenticatedGroup.GET("/admin/modules/:id",
				middleware.RequireScope(auth.ScopeModulesRead),
				nsAuthz.RequireModuleAccessByID(auth.ScopeModulesRead),
				moduleAdminHandlers.GetModuleByIDRecord)
			authenticatedGroup.PUT("/admin/modules/:id",
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequireModuleUpdateAccess(auth.ScopeModulesWrite),
				moduleAdminHandlers.UpdateModuleRecord)
			authenticatedGroup.POST("/modules",
				middleware.RateLimitMiddleware(uploadRateLimiter), // Stricter rate limit for uploads
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequirePublishAccessFromForm(auth.ScopeModulesWrite, 100<<20), // matches the handler's ParseMultipartForm limit
				modules.UploadHandler(db, storageBackend, cfg, scanRepo, moduleDocsRepo, policyEngine, notifier))

			// Providers admin endpoints - require write permissions plus
			// namespace-org authorization (issue #555)
			authenticatedGroup.POST("/providers",
				middleware.RateLimitMiddleware(uploadRateLimiter), // Stricter rate limit for uploads
				middleware.RequireScope(auth.ScopeProvidersWrite),
				nsAuthz.RequirePublishAccessFromForm(auth.ScopeProvidersWrite, 32<<20), // gin's default multipart memory limit
				providers.UploadHandler(db, storageBackend, cfg))
			authenticatedGroup.DELETE("/providers/:namespace/:type",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeProvidersWrite),
				providerAdminHandlers.DeleteProvider)
			authenticatedGroup.DELETE("/providers/:namespace/:type/versions/:version",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeProvidersWrite),
				providerAdminHandlers.DeleteVersion)
			authenticatedGroup.POST("/providers/:namespace/:type/versions/:version/deprecate",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeProvidersWrite),
				providerAdminHandlers.DeprecateVersion)
			authenticatedGroup.DELETE("/providers/:namespace/:type/versions/:version/deprecate",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeProvidersWrite),
				providerAdminHandlers.UndeprecateVersion)

			// Provider record admin endpoints (create + get by UUID)
			authenticatedGroup.POST("/admin/providers",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				nsAuthz.RequirePublishAccessFromJSON(auth.ScopeProvidersWrite),
				providerAdminHandlers.CreateProviderRecord)
			// Guarded on the same axis as PUT /admin/providers/:id above
			// (issue #719): GetProviderByID emits the whole providers row for
			// any id in any organization with no organization predicate.
			authenticatedGroup.GET("/admin/providers/:id",
				middleware.RequireScope(auth.ScopeProvidersRead),
				nsAuthz.RequireProviderAccessByID(auth.ScopeProvidersRead),
				providerAdminHandlers.GetProviderByID)
			authenticatedGroup.PUT("/admin/providers/:id",
				middleware.RequireScope(auth.ScopeProvidersWrite),
				nsAuthz.RequireProviderAccessByID(auth.ScopeProvidersWrite),
				providerAdminHandlers.UpdateProviderRecord)

			// Modules admin endpoints - delete, deprecate (GET moved to publicDetailGroup above)
			authenticatedGroup.DELETE("/modules/:namespace/:name/:system",
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
				moduleAdminHandlers.DeleteModule)
			authenticatedGroup.DELETE("/modules/:namespace/:name/:system/versions/:version",
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
				moduleAdminHandlers.DeleteVersion)
			authenticatedGroup.POST("/modules/:namespace/:name/:system/versions/:version/deprecate",
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
				moduleAdminHandlers.DeprecateVersion)
			authenticatedGroup.DELETE("/modules/:namespace/:name/:system/versions/:version/deprecate",
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
				moduleAdminHandlers.UndeprecateVersion)
			authenticatedGroup.POST("/modules/:namespace/:name/:system/versions/:version/reanalyze",
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
				moduleAdminHandlers.ReanalyzeVersion)

			// Module-level deprecation
			authenticatedGroup.POST("/modules/:namespace/:name/:system/deprecate",
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
				moduleAdminHandlers.DeprecateModule)
			authenticatedGroup.DELETE("/modules/:namespace/:name/:system/deprecate",
				middleware.RequireScope(auth.ScopeModulesWrite),
				nsAuthz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
				moduleAdminHandlers.UndeprecateModule)

			authenticatedGroup.GET("/modules/:namespace/:name/:system/versions/:version/scan",
				middleware.RequireScope(auth.ScopeScanningRead),
				admin.GetModuleScanHandler(db))

			// Security scanning admin endpoints
			authenticatedGroup.GET("/admin/scanning/config",
				middleware.RequireScope(auth.ScopeAdmin),
				admin.GetScanningConfigHandler(&cfg.Scanning))
			authenticatedGroup.GET("/admin/scanning/stats",
				middleware.RequireScope(auth.ScopeScanningRead),
				admin.GetScanningStatsHandler(sqlxDB))
			authenticatedGroup.GET("/admin/scanning/scans/:id",
				middleware.RequireScope(auth.ScopeScanningRead),
				admin.GetScanByIDHandler(db, orgRepo))
			installHandler := admin.NewScanningInstallHandler(&cfg.Scanning, nil, scannerUpdateJob, sbvRepo, scannerApprovalRepo)
			installHandler.SetEgressGuard(egressGuard)
			authenticatedGroup.POST("/admin/scanning/install",
				middleware.RequireScope(auth.ScopeAdmin),
				installHandler.Install())
			authenticatedGroup.POST("/admin/scanning/check",
				middleware.RequireScope(auth.ScopeAdmin),
				admin.TriggerScannerCheckHandler(scannerUpdateJob))
			authenticatedGroup.GET("/admin/scanning/latest",
				middleware.RequireScope(auth.ScopeScanningRead),
				admin.GetScannerLatestHandler(&cfg.Scanning, egressGuard))
			scanningAutoUpdateHandler := admin.NewScanningAutoUpdateHandler(&cfg.Scanning, oidcConfigRepo, scannerUpdateJob)
			authenticatedGroup.PUT("/admin/scanning/auto-update",
				middleware.RequireScope(auth.ScopeAdmin),
				scanningAutoUpdateHandler.Put)

			// Notifications (SMTP) admin endpoints
			authenticatedGroup.GET("/admin/notifications/config",
				middleware.RequireScope(auth.ScopeAdmin),
				notificationsHandler.GetConfig)
			authenticatedGroup.PUT("/admin/notifications/config",
				middleware.RequireScope(auth.ScopeAdmin),
				notificationsHandler.PutConfig)
			authenticatedGroup.POST("/admin/notifications/test",
				middleware.RequireScope(auth.ScopeAdmin),
				notificationsHandler.TestEmail)

			// Notification channels: additional delivery destinations (webhook,
			// Slack, Microsoft Teams, or an ad-hoc email recipient list) for the
			// module_published, approval_pending, cve_detected, and
			// scanner_update_available events.
			authenticatedGroup.GET("/admin/notifications/channels",
				middleware.RequireScope(auth.ScopeAdmin),
				notificationChannelHandlers.ListChannels)
			authenticatedGroup.POST("/admin/notifications/channels",
				middleware.RequireScope(auth.ScopeAdmin),
				notificationChannelHandlers.CreateChannel)
			authenticatedGroup.PUT("/admin/notifications/channels/:id",
				middleware.RequireScope(auth.ScopeAdmin),
				notificationChannelHandlers.UpdateChannel)
			authenticatedGroup.DELETE("/admin/notifications/channels/:id",
				middleware.RequireScope(auth.ScopeAdmin),
				notificationChannelHandlers.DeleteChannel)
			authenticatedGroup.POST("/admin/notifications/channels/:id/test",
				middleware.RequireScope(auth.ScopeAdmin),
				notificationChannelHandlers.TestChannel)

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

			// GDPR data-subject endpoints (Articles 15/17/20). Admin scope only —
			// these reveal or destroy PII for any user, so the gate is stricter than
			// users:write.
			adminUsersGroup := authenticatedGroup.Group("/admin/users")
			adminUsersGroup.Use(middleware.RequireScope(auth.ScopeAdmin))
			{
				adminUsersGroup.GET("/:id/export", gdprHandlers.ExportUserDataHandler())
				adminUsersGroup.POST("/:id/erase", gdprHandlers.EraseUserHandler())
			}

			// White-label theme writes for admins (post-setup edits).
			// Setup-wizard writes use PUT /api/v1/setup/ui-theme above.
			adminUIThemeHandlers := uitheme.NewHandlers(sqlxDB)
			authenticatedGroup.PUT("/admin/ui-theme",
				middleware.RequireScope(auth.ScopeAdmin),
				adminUIThemeHandlers.PutTheme())

			// Per-org quota status — feeds the frontend QuotaUsageChart dashboard.
			// READ-ONLY in this PR; enforcement middleware (429 / X-Quota-Reset)
			// and admin writes for setting per-org limits are tracked separately.
			quotaHandlers := admin.NewQuotaHandlers(sqlxDB)
			authenticatedGroup.GET("/admin/quotas",
				middleware.RequireScope(auth.ScopeAdmin),
				quotaHandlers.ListQuotas())

			// Organizations management.
			//
			// Every route below with an :id path parameter also gets
			// RequireOrgScopeForPathOrg after RequireScope: RequireScope alone
			// only checks the caller's flat/global combined scope (union'd
			// across every org they belong to), which lets a user who holds
			// organizations:write in just one organization act on any OTHER
			// organization by ID (GHSA-hc25-j576-cqm2). RequireOrgScopeForPathOrg
			// re-derives the caller's scopes specifically for the org named by
			// :id and requires the route's scope there instead. Routes with no
			// :id (list/search/create) are unaffected -- there is no specific
			// target organization to check membership in.
			orgsGroup := authenticatedGroup.Group("/organizations")
			{
				// Read operations require organizations:read
				orgsGroup.GET("", middleware.RequireScope(auth.ScopeOrganizationsRead), orgHandlers.ListOrganizationsHandler())
				orgsGroup.GET("/search", middleware.RequireScope(auth.ScopeOrganizationsRead), orgHandlers.SearchOrganizationsHandler())
				orgsGroup.GET("/:id",
					middleware.RequireScope(auth.ScopeOrganizationsRead),
					middleware.RequireOrgScopeForPathOrg(auth.ScopeOrganizationsRead, orgRepo),
					orgHandlers.GetOrganizationHandler())
				orgsGroup.GET("/:id/members",
					middleware.RequireScope(auth.ScopeOrganizationsRead),
					middleware.RequireOrgScopeForPathOrg(auth.ScopeOrganizationsRead, orgRepo),
					orgHandlers.ListMembersHandler())

				// Creating a new top-level organization is a platform-tier
				// provisioning action, gated on its own organizations:create
				// scope instead of organizations:write (issue #648): holding
				// organizations:write via membership in one org must not by
				// itself grant the ability to provision brand new orgs.
				orgsGroup.POST("", middleware.RequireScope(auth.ScopeOrganizationsCreate), orgHandlers.CreateOrganizationHandler())

				// Update/delete require organizations:write
				orgsGroup.PUT("/:id",
					middleware.RequireScope(auth.ScopeOrganizationsWrite),
					middleware.RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo),
					orgHandlers.UpdateOrganizationHandler())
				orgsGroup.DELETE("/:id",
					middleware.RequireScope(auth.ScopeOrganizationsWrite),
					middleware.RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo),
					orgHandlers.DeleteOrganizationHandler())

				// Member management requires organizations:write
				orgsGroup.POST("/:id/members",
					middleware.RequireScope(auth.ScopeOrganizationsWrite),
					middleware.RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo),
					orgHandlers.AddMemberHandler())
				orgsGroup.PUT("/:id/members/:user_id",
					middleware.RequireScope(auth.ScopeOrganizationsWrite),
					middleware.RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo),
					orgHandlers.UpdateMemberHandler())
				orgsGroup.DELETE("/:id/members/:user_id",
					middleware.RequireScope(auth.ScopeOrganizationsWrite),
					middleware.RequireOrgScopeForPathOrg(auth.ScopeOrganizationsWrite, orgRepo),
					orgHandlers.RemoveMemberHandler())
			}

			// Namespace ownership (read-only): audit which organization owns each
			// module/provider namespace. Ownership itself is enforced by
			// namespace_claims on every mutation (issue #555); these endpoints only
			// expose it for verification.
			authenticatedGroup.GET("/admin/namespaces",
				middleware.RequireScope(auth.ScopeOrganizationsRead),
				orgHandlers.ListNamespaceClaimsHandler())
			authenticatedGroup.GET("/admin/namespaces/:namespace",
				middleware.RequireScope(auth.ScopeOrganizationsRead),
				orgHandlers.GetNamespaceOwnershipHandler())

			// SCM Provider management
			scmProvidersGroup := authenticatedGroup.Group("/scm-providers")
			{
				// Every /:id route additionally re-derives the caller's scope in
				// the organization that owns THAT provider (issue #718). The
				// group-level RequireScope only checks the flat, org-less scope
				// union from the session JWT (issue #652), so without this a
				// caller holding scm:manage via membership in one organization
				// could repoint, re-credential, or delete another
				// organization's provider — and /repositories would enumerate
				// the target org's private repos using that org's own shared
				// app credentials.
				scmProviderOrg := func(scope auth.Scope) gin.HandlerFunc {
					return nsAuthz.RequireOrgScopeForResource(scope, scmProviderOrgResolver(d.scmRepo))
				}

				// Read operations require scm:read
				scmProvidersGroup.GET("", middleware.RequireScope(auth.ScopeSCMRead), scmProviderHandlers.ListProviders)
				scmProvidersGroup.GET("/:id", middleware.RequireScope(auth.ScopeSCMRead), scmProviderOrg(auth.ScopeSCMRead), scmProviderHandlers.GetProvider)

				// Management operations require scm:manage
				scmProvidersGroup.POST("", middleware.RequireScope(auth.ScopeSCMManage), scmProviderHandlers.CreateProvider)
				scmProvidersGroup.PUT("/:id", middleware.RequireScope(auth.ScopeSCMManage), scmProviderOrg(auth.ScopeSCMManage), scmProviderHandlers.UpdateProvider)
				scmProvidersGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeSCMManage), scmProviderOrg(auth.ScopeSCMManage), scmProviderHandlers.DeleteProvider)

				// Verify shared app credentials by minting a token (app auth modes only)
				scmProvidersGroup.POST("/:id/verify", middleware.RequireScope(auth.ScopeSCMManage), scmProviderOrg(auth.ScopeSCMManage), scmProviderHandlers.VerifyProvider)

				// OAuth flow endpoints require scm:manage
				scmProvidersGroup.GET("/:id/oauth/authorize", middleware.RequireScope(auth.ScopeSCMManage), scmProviderOrg(auth.ScopeSCMManage), scmOAuthHandlers.InitiateOAuth)
				scmProvidersGroup.GET("/:id/oauth/token", middleware.RequireScope(auth.ScopeSCMRead), scmProviderOrg(auth.ScopeSCMRead), scmOAuthHandlers.GetTokenStatus)
				scmProvidersGroup.DELETE("/:id/oauth/token", middleware.RequireScope(auth.ScopeSCMManage), scmProviderOrg(auth.ScopeSCMManage), scmOAuthHandlers.RevokeOAuth)
				scmProvidersGroup.POST("/:id/oauth/refresh", middleware.RequireScope(auth.ScopeSCMManage), scmProviderOrg(auth.ScopeSCMManage), scmOAuthHandlers.RefreshToken)

				// PAT-based auth (e.g., Bitbucket Data Center)
				scmProvidersGroup.POST("/:id/token", middleware.RequireScope(auth.ScopeSCMManage), scmProviderOrg(auth.ScopeSCMManage), scmOAuthHandlers.SavePATToken)

				// Repository listing - requires scm:read
				scmProvidersGroup.GET("/:id/repositories", middleware.RequireScope(auth.ScopeSCMRead), scmProviderOrg(auth.ScopeSCMRead), scmOAuthHandlers.ListRepositories)
				scmProvidersGroup.GET("/:id/repositories/:owner/:repo/tags", middleware.RequireScope(auth.ScopeSCMRead), scmProviderOrg(auth.ScopeSCMRead), scmOAuthHandlers.ListRepositoryTags)
				scmProvidersGroup.GET("/:id/repositories/:owner/:repo/branches", middleware.RequireScope(auth.ScopeSCMRead), scmProviderOrg(auth.ScopeSCMRead), scmOAuthHandlers.ListRepositoryBranches)
			}

			// SCM OAuth callback (public endpoint, no auth required).
			//
			// The caller is anonymous, so possession of the single-use state
			// nonce minted by /oauth/authorize is the whole credential — see
			// HandleOAuthCallback's GUARD (scm-oauth-callback). It is rate
			// limited on the same authRateLimiter as /api/v1/auth/*, the other
			// family of unauthenticated credential-redeeming routes: without a
			// limiter an anonymous caller may grind state guesses (and drive
			// upstream token-endpoint exchanges) at will.
			apiV1.GET("/scm-providers/:id/oauth/callback",
				middleware.RateLimitMiddleware(authRateLimiter),
				scmOAuthHandlers.HandleOAuthCallback)

			// Module SCM linking endpoints. Every route requires namespace-org
			// authorization for the target module (issue #555): the reads are
			// gated too, because GetModuleSCMInfo returns the link's
			// webhook_url and that URL embeds the webhook secret, which is the
			// sole credential for the unauthenticated
			// POST /webhooks/scm/:module_source_repo_id/:secret endpoint. Left
			// ungated, any holder of the flat modules:write scope union could
			// read another organization's secret and drive its sync pipeline.
			moduleSCMGroup := authenticatedGroup.Group("/admin/modules/:id/scm")
			moduleSCMGroup.Use(middleware.RequireScope(auth.ScopeModulesWrite))
			{
				moduleSCMGroup.POST("", nsAuthz.RequireModuleAccessByID(auth.ScopeModulesWrite), scmLinkingHandler.LinkModuleToSCM)
				moduleSCMGroup.GET("", nsAuthz.RequireModuleAccessByID(auth.ScopeModulesWrite), scmLinkingHandler.GetModuleSCMInfo)
				moduleSCMGroup.PUT("", nsAuthz.RequireModuleAccessByID(auth.ScopeModulesWrite), scmLinkingHandler.UpdateSCMLink)
				moduleSCMGroup.DELETE("", nsAuthz.RequireModuleAccessByID(auth.ScopeModulesWrite), scmLinkingHandler.UnlinkModuleFromSCM)
				moduleSCMGroup.POST("/sync", nsAuthz.RequireModuleAccessByID(auth.ScopeModulesWrite), scmLinkingHandler.TriggerManualSync)
				moduleSCMGroup.GET("/events", nsAuthz.RequireModuleAccessByID(auth.ScopeModulesWrite), scmLinkingHandler.GetWebhookEvents)
			}

			// Mirror management endpoints with granular RBAC
			// Read operations require mirrors:read scope
			// Management operations require mirrors:manage scope
			mirrorsGroup := authenticatedGroup.Group("/admin/mirrors")
			{
				// Read operations - require mirrors:read (or mirrors:manage or admin)
				// As with the SCM provider family, every /:id route re-derives
				// the caller's scope in the organization owning THAT mirror
				// configuration; the group-level RequireScope only sees the
				// flat org-less scope union (issues #652/#719).
				mirrorConfigOrg := func(scope auth.Scope) gin.HandlerFunc {
					return nsAuthz.RequireOrgScopeForResource(scope, mirrorConfigOrgResolver(d.mirrorRepo))
				}

				mirrorsGroup.GET("", middleware.RequireScope(auth.ScopeMirrorsRead), mirrorHandlers.ListMirrorConfigs)
				mirrorsGroup.GET("/:id", middleware.RequireScope(auth.ScopeMirrorsRead), mirrorConfigOrg(auth.ScopeMirrorsRead), mirrorHandlers.GetMirrorConfig)
				mirrorsGroup.GET("/:id/status", middleware.RequireScope(auth.ScopeMirrorsRead), mirrorConfigOrg(auth.ScopeMirrorsRead), mirrorHandlers.GetMirrorStatus)
				mirrorsGroup.GET("/:id/providers", middleware.RequireScope(auth.ScopeMirrorsRead), mirrorConfigOrg(auth.ScopeMirrorsRead), mirrorHandlers.ListMirroredProviders)

				// Management operations - require mirrors:manage (or admin)
				mirrorsGroup.POST("", middleware.RequireScope(auth.ScopeMirrorsManage), mirrorHandlers.CreateMirrorConfig)
				mirrorsGroup.PUT("/:id", middleware.RequireScope(auth.ScopeMirrorsManage), mirrorConfigOrg(auth.ScopeMirrorsManage), mirrorHandlers.UpdateMirrorConfig)
				mirrorsGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeMirrorsManage), mirrorConfigOrg(auth.ScopeMirrorsManage), mirrorHandlers.DeleteMirrorConfig)
				mirrorsGroup.POST("/:id/sync", middleware.RequireScope(auth.ScopeMirrorsManage), mirrorConfigOrg(auth.ScopeMirrorsManage), mirrorHandlers.TriggerSync)
			}

			// Terraform Binary Mirror admin endpoints (multi-config).
			//
			// PLATFORM-GLOBAL, unlike the /admin/mirrors family above.
			// terraform_mirror_configs has no organization_id column at all
			// (migration 000004): a single row is the Terraform/OpenTofu binary
			// supply chain for EVERY tenant, and the versions, platforms and
			// sync-history tables hanging off it inherit that. There is no
			// owning organization for a per-resource guard to re-derive, so the
			// #719 mirrorConfigOrg(...) treatment does not apply here.
			//
			// The absence of a tenancy axis is not "no guard needed" — it means
			// platform-wide authority is required. That is already the settled
			// contract for org-less rows everywhere else in this codebase:
			// tenantscope.Permits admits an unowned row to a platform admin
			// only, and middleware.RequireOrgScopeForResource does the same for
			// the ":id" axes. mirrors:manage does NOT carry that authority — the
			// seeded devops and org_owner role templates grant it through
			// membership in a SINGLE organization (migrations 000001/000049),
			// which is the whole gap (issue #734).
			//
			// Every mutation is therefore gated on the platform-wide admin
			// scope: repointing upstream_url, lowering the verification
			// settings (gpg_verify, verify_github_attestation) or the
			// requires_approval gate, triggering a sync, and deleting or
			// deprecating configs/versions all change what binaries every
			// tenant receives from /terraform/binaries.
			//
			// Reads deliberately stay on mirrors:read. These tables carry no
			// tenant data and no credentials — names, upstream URLs, filters,
			// verification flags, version catalogues, sync status and cached
			// PUBLIC release-signing keys — and the mirror is a shared service
			// whose catalogue and health tenant operators legitimately need to
			// see. This is the same read/write split the /admin/policies and
			// /admin/version-approvals groups above already use.
			tfMirrorGroup := authenticatedGroup.Group("/admin/terraform-mirrors")
			{
				// Release-signing GPG key cache + expiry state (read-only).
				// Registered before /:id routes so the static path takes priority.
				tfMirrorGroup.GET("/releases-gpg-keys", middleware.RequireScope(auth.ScopeMirrorsRead), releasesGPGKeysAdminHandler.GetReleasesGPGKeys)
				// Config CRUD
				tfMirrorGroup.GET("", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.ListConfigs)
				tfMirrorGroup.POST("", middleware.RequireScope(auth.ScopeAdmin), tfMirrorAdminHandler.CreateConfig)
				tfMirrorGroup.GET("/:id", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.GetConfig)
				tfMirrorGroup.GET("/:id/status", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.GetStatus)
				tfMirrorGroup.PUT("/:id", middleware.RequireScope(auth.ScopeAdmin), tfMirrorAdminHandler.UpdateConfig)
				tfMirrorGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeAdmin), tfMirrorAdminHandler.DeleteConfig)
				// Sync trigger
				tfMirrorGroup.POST("/:id/sync", middleware.RequireScope(auth.ScopeAdmin), tfMirrorAdminHandler.TriggerSync)
				// Versions
				tfMirrorGroup.GET("/:id/versions", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.ListVersions)
				tfMirrorGroup.GET("/:id/versions/:version", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.GetVersion)
				tfMirrorGroup.DELETE("/:id/versions/:version", middleware.RequireScope(auth.ScopeAdmin), tfMirrorAdminHandler.DeleteVersion)
				tfMirrorGroup.POST("/:id/versions/:version/deprecate", middleware.RequireScope(auth.ScopeAdmin), tfMirrorAdminHandler.DeprecateVersion)
				tfMirrorGroup.DELETE("/:id/versions/:version/deprecate", middleware.RequireScope(auth.ScopeAdmin), tfMirrorAdminHandler.UndeprecateVersion)
				tfMirrorGroup.GET("/:id/versions/:version/platforms", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.ListPlatforms)
				// Sync history
				tfMirrorGroup.GET("/:id/history", middleware.RequireScope(auth.ScopeMirrorsRead), tfMirrorAdminHandler.GetSyncHistory)
			}

			// Role Templates management
			roleTemplatesGroup := authenticatedGroup.Group("/admin/role-templates")
			{
				roleTemplatesGroup.GET("", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.ListRoleTemplates)
				roleTemplatesGroup.GET("/:id", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.GetRoleTemplate)
				roleTemplatesGroup.POST("", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.CreateRoleTemplate)
				roleTemplatesGroup.PUT("/:id", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.UpdateRoleTemplate)
				roleTemplatesGroup.DELETE("/:id", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.DeleteRoleTemplate)
			}

			// Mirror Approval Requests
			approvalsGroup := authenticatedGroup.Group("/admin/approvals")
			{
				// Per-org re-derivation for the /:id routes (issue #719). Not
				// applied to PUT /:id/review, which already requires the
				// platform-wide admin scope that this guard deliberately
				// exempts — adding it there would be dead weight, not defence.
				approvalOrg := func(scope auth.Scope) gin.HandlerFunc {
					return nsAuthz.RequireOrgScopeForResource(scope, approvalRequestOrgResolver(d.rbacRepo))
				}

				approvalsGroup.GET("", middleware.RequireScope(auth.ScopeMirrorsRead), rbacHandlers.ListApprovalRequests)
				approvalsGroup.GET("/:id", middleware.RequireScope(auth.ScopeMirrorsRead), approvalOrg(auth.ScopeMirrorsRead), rbacHandlers.GetApprovalRequest)
				approvalsGroup.POST("", middleware.RequireScope(auth.ScopeMirrorsManage), rbacHandlers.CreateApprovalRequest)
				approvalsGroup.PUT("/:id/review", middleware.RequireScope(auth.ScopeAdmin), rbacHandlers.ReviewApproval)
				// Generate a single-use token that allows out-of-band (email/Slack) approval.
				// Guarded per-org: the redemption endpoint
				// (POST /webhooks/approvals/:token) is unauthenticated, so
				// minting a token for another organization's request would hand
				// over a working credential.
				approvalsGroup.POST("/:id/token", middleware.RequireScope(auth.ScopeMirrorsManage), approvalOrg(auth.ScopeMirrorsManage), rbacHandlers.GenerateApprovalToken)
			}

			// Version Approvals (provider + terraform mirror version gate)
			versionApprovalsGroup := authenticatedGroup.Group("/admin/version-approvals")
			{
				versionApprovalsGroup.GET("", middleware.RequireScope(auth.ScopeMirrorsRead), versionApprovalHandler.List)
				versionApprovalsGroup.GET("/pending-count", middleware.RequireScope(auth.ScopeMirrorsRead), versionApprovalHandler.PendingCount)
				versionApprovalsGroup.GET("/:id/events", middleware.RequireScope(auth.ScopeMirrorsRead), versionApprovalHandler.Events)
				versionApprovalsGroup.PUT("/:id/approve", middleware.RequireScope(auth.ScopeAdmin), versionApprovalHandler.Approve)
				versionApprovalsGroup.PUT("/:id/reject", middleware.RequireScope(auth.ScopeAdmin), versionApprovalHandler.Reject)
				versionApprovalsGroup.POST("/bulk-approve", middleware.RequireScope(auth.ScopeAdmin), versionApprovalHandler.BulkApprove)
				versionApprovalsGroup.POST("/bulk-reject", middleware.RequireScope(auth.ScopeAdmin), versionApprovalHandler.BulkReject)
			}

			// Mirror Policies
			policiesGroup := authenticatedGroup.Group("/admin/policies")
			{
				// GET /:id is gated on mirrors:read, not admin, so the flat
				// org-less scope union alone let any member of any organization
				// read another organization's mirror policy. The mutations below
				// keep the platform-admin gate, which the per-org guard exempts
				// anyway (issue #719).
				policyOrg := func(scope auth.Scope) gin.HandlerFunc {
					return nsAuthz.RequireOrgScopeForResource(scope, mirrorPolicyOrgResolver(d.rbacRepo))
				}

				policiesGroup.GET("", middleware.RequireScope(auth.ScopeMirrorsRead), rbacHandlers.ListMirrorPolicies)
				policiesGroup.GET("/:id", middleware.RequireScope(auth.ScopeMirrorsRead), policyOrg(auth.ScopeMirrorsRead), rbacHandlers.GetMirrorPolicy)
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

			// Storage Migration management (requires admin scope)
			storageMigrationRepo := repositories.NewStorageMigrationRepository(sqlxDB)
			storageMigrationService := services.NewStorageMigrationService(
				storageMigrationRepo, storageConfigRepo, moduleRepo, providerRepo, tokenCipher, cfg,
			)
			storageMigrationHandler := admin.NewStorageMigrationHandler(storageMigrationService)

			migrationGroup := authenticatedGroup.Group("/admin/storage/migrations")
			migrationGroup.Use(middleware.RequireScope(auth.ScopeAdmin))
			{
				migrationGroup.POST("/plan", storageMigrationHandler.PlanMigration)
				migrationGroup.POST("", storageMigrationHandler.StartMigration)
				migrationGroup.GET("", storageMigrationHandler.ListMigrations)
				migrationGroup.GET("/:id", storageMigrationHandler.GetMigrationStatus)
				migrationGroup.POST("/:id/cancel", storageMigrationHandler.CancelMigration)
			}

			// OIDC admin configuration management (requires admin scope)
			oidcAdminGroup := authenticatedGroup.Group("/admin/oidc")
			oidcAdminGroup.Use(middleware.RequireScope(auth.ScopeAdmin))
			{
				oidcAdminGroup.GET("/config", oidcAdminHandlers.GetActiveOIDCConfig)
				oidcAdminGroup.PUT("/group-mapping", oidcAdminHandlers.UpdateGroupMapping)
			}

			// Identity group mappings (SAML + LDAP, read-only from config)
			authenticatedGroup.GET("/admin/identity/group-mappings",
				middleware.RequireScope(auth.ScopeAdmin),
				authHandlers.IdentityGroupMappingsHandler())

			// mTLS config (read-only from server config)
			authenticatedGroup.GET("/admin/mtls/config",
				middleware.RequireScope(auth.ScopeAdmin),
				authHandlers.MTLSConfigHandler())

			// Audit log read access (requires audit:read scope; admins implicitly have it)
			auditLogsGroup := authenticatedGroup.Group("/admin/audit-logs")
			{
				auditLogsGroup.GET("", middleware.RequireScope(auth.ScopeAuditRead), auditLogHandlers.ListAuditLogsHandler())
				auditLogsGroup.GET("/export", middleware.RequireScope(auth.ScopeAuditRead), auditLogHandlers.ExportAuditLogs(AppVersion))
				auditLogsGroup.GET("/:id", middleware.RequireScope(auth.ScopeAuditRead), auditLogHandlers.GetAuditLogHandler())
			}

			// Policy engine admin endpoints (requires admin scope)
			policyGroup := authenticatedGroup.Group("/admin/policy")
			policyGroup.Use(middleware.RequireScope(auth.ScopeAdmin))
			{
				policyGroup.GET("/config", policyAdminHandler.GetPolicyConfig)
				policyGroup.POST("/reload", policyAdminHandler.ReloadBundle)
				policyGroup.POST("/evaluate", policyAdminHandler.EvaluateInput)
			}

			// CVE advisory admin endpoints (requires admin scope)
			advisoryAdminHandlers := admin.NewAdvisoryHandlers(db, cvePollJob)
			advisoryAdminGroup := authenticatedGroup.Group("/admin/advisories")
			advisoryAdminGroup.Use(middleware.RequireScope(auth.ScopeAdmin))
			{
				advisoryAdminGroup.GET("", advisoryAdminHandlers.ListAdvisories())
				advisoryAdminGroup.POST("/poll", advisoryAdminHandlers.TriggerPoll())
			}
		}

		registerSCIMRoutes(router, d)

		// Development-only endpoints (guarded by DevModeMiddleware)
		devGroup := apiV1.Group("/dev")
		devGroup.Use(admin.DevModeMiddleware())
		{
			devHandlers := admin.NewDevHandlers(cfg, db)
			// Unauthenticated dev endpoints (dev-mode-gated only)
			devGroup.GET("/status", devHandlers.DevStatusHandler())
			devGroup.POST("/login", devHandlers.DevLoginHandler())

			// Impersonation endpoints (require auth + admin scope)
			devGroup.Use(middleware.AuthMiddleware(cfg, userRepo, apiKeyRepo, orgRepo, tokenRepo, userTokenRevocationRepo))
			devGroup.GET("/users", devHandlers.ListUsersForImpersonationHandler())
			devGroup.POST("/impersonate/:user_id", devHandlers.ImpersonateUserHandler())
		}
	}

	// Webhook endpoints (public, authentication via signature validation)
	router.POST("/webhooks/scm/:module_source_repo_id/:secret", scmWebhookHandler.HandleWebhook)
	// Single-use approval token redemption — no auth, token possession is the credential.
	router.POST("/webhooks/approvals/:token", approvalWebhookHandler.RedeemApprovalToken)
}

// registerSCIMRoutes wires the SCIM 2.0 provisioning group onto router.
// Extracted from registerAPIV1Routes (same pattern as registerPublicRoutes /
// registerAPIV1Routes themselves, issue #565 finding [39]) so the group's
// middleware ordering can be exercised directly by a test against the real
// production wiring instead of a stand-in gin.Engine.
//
// SCIM 2.0 provisioning endpoints — bearer token auth only (no CSRF, no cookie auth).
// Require admin or scim:provision scope. Audited and rate-limited the same as
// every other authenticated mutating route (authenticatedGroup above): external
// IdP-driven user/group provisioning should leave the same audit trail and be
// subject to the same abuse protection as admin-initiated mutations.
func registerSCIMRoutes(router *gin.Engine, d *apiV1RouteDeps) {
	scimGroup := router.Group("/scim/v2")
	scimGroup.Use(middleware.AuthMiddleware(d.cfg, d.userRepo, d.apiKeyRepo, d.orgRepo, d.tokenRepo, d.userTokenRevocationRepo))
	scimGroup.Use(middleware.PrincipalRateLimitMiddleware(d.generalRateLimiter, d.principalOverrides))
	scimGroup.Use(middleware.OrgRateLimitMiddleware(d.generalRateLimiter, d.orgRateLimiter))
	scimGroup.Use(middleware.AuditMiddleware(d.auditRepo))
	// RequireScope runs last so a scope-check failure still passes through
	// rate limiting and auditing above, matching how every other
	// authenticated mutating route in this file orders RBAC after the
	// group's rate-limit/audit middleware (see advisoryAdminGroup /
	// policyGroup above, and the per-route RequireScope calls under
	// authenticatedGroup).
	scimGroup.Use(middleware.RequireScope(auth.ScopeSCIMProvision))
	{
		scimHandlers := scim.NewHandlers(d.cfg, d.db, scim.WithCredentialSweeper(d.credSweeper))
		scimGroup.GET("/Users", scimHandlers.ListUsers())
		scimGroup.GET("/Users/:id", scimHandlers.GetUser())
		scimGroup.POST("/Users", scimHandlers.CreateUser())
		scimGroup.PUT("/Users/:id", scimHandlers.PutUser())
		scimGroup.PATCH("/Users/:id", scimHandlers.PatchUser())
		scimGroup.DELETE("/Users/:id", scimHandlers.DeleteUser())
		scimGroup.GET("/Groups", scimHandlers.ListGroups())
		scimGroup.GET("/Groups/:id", scimHandlers.GetGroup())
	}
}

// scmProviderOrgResolver adapts SCMRepository to middleware.ResourceOrgResolver
// for the /scm-providers/:id family (issue #718).
//
// scm_providers.organization_id is nullable, so a legacy row with no owner
// resolves to ("", true, nil) — "found, but unowned" — which the guard treats
// as admin-only rather than open. A nil repository resolves to an error rather
// than a pass, so a wiring mistake fails closed instead of silently disabling
// the check.
func scmProviderOrgResolver(scmRepo *repositories.SCMRepository) middleware.ResourceOrgResolver {
	return func(ctx context.Context, id string) (string, bool, error) {
		if scmRepo == nil {
			return "", false, errors.New("scm repository not configured")
		}
		providerID, err := uuid.Parse(id)
		if err != nil {
			return "", false, nil
		}
		provider, err := scmRepo.GetProvider(ctx, providerID)
		if err != nil {
			return "", false, err
		}
		if provider == nil {
			return "", false, nil
		}
		if provider.OrganizationID == uuid.Nil {
			return "", true, nil
		}
		return provider.OrganizationID.String(), true, nil
	}
}

// mirrorConfigOrgResolver adapts MirrorRepository to
// middleware.ResourceOrgResolver for /admin/mirrors/:id (issue #719).
// mirror_configurations.organization_id is nullable, so an unowned row
// resolves to ("", true, nil) and the guard treats it as admin-only.
func mirrorConfigOrgResolver(mirrorRepo *repositories.MirrorRepository) middleware.ResourceOrgResolver {
	return func(ctx context.Context, id string) (string, bool, error) {
		if mirrorRepo == nil {
			return "", false, errors.New("mirror repository not configured")
		}
		configID, err := uuid.Parse(id)
		if err != nil {
			return "", false, nil
		}
		config, err := mirrorRepo.GetByID(ctx, configID)
		if err != nil {
			return "", false, err
		}
		if config == nil {
			return "", false, nil
		}
		if config.OrganizationID == nil || *config.OrganizationID == uuid.Nil {
			return "", true, nil
		}
		return config.OrganizationID.String(), true, nil
	}
}

// approvalRequestOrgResolver adapts RBACRepository to
// middleware.ResourceOrgResolver for /admin/approvals/:id (issue #719).
//
// This one matters more than a typical read guard: GenerateApprovalToken mints
// a single-use token whose redemption endpoint
// (POST /webhooks/approvals/:token) is unauthenticated — possession of the
// token is the credential — so an unguarded route let a caller mint an
// approval for another organization's pending mirror request.
func approvalRequestOrgResolver(rbacRepo *repositories.RBACRepository) middleware.ResourceOrgResolver {
	return func(ctx context.Context, id string) (string, bool, error) {
		if rbacRepo == nil {
			return "", false, errors.New("rbac repository not configured")
		}
		requestID, err := uuid.Parse(id)
		if err != nil {
			return "", false, nil
		}
		req, err := rbacRepo.GetApprovalRequest(ctx, requestID)
		if err != nil {
			return "", false, err
		}
		if req == nil {
			return "", false, nil
		}
		if req.OrganizationID == nil || *req.OrganizationID == uuid.Nil {
			return "", true, nil
		}
		return req.OrganizationID.String(), true, nil
	}
}

// mirrorPolicyOrgResolver adapts RBACRepository to
// middleware.ResourceOrgResolver for /admin/policies/:id (issue #719).
//
// The mirror-policy family was the one #719 route family that got no per-org
// guard at all: its mutations sit behind the platform-wide admin scope, which
// hid the fact that GET /:id only requires mirrors:read — a scope the flat
// session union hands out on the strength of membership in any single
// organization. mirror_policies.organization_id is nullable and NULL means a
// GLOBAL policy, which every tenant is already governed by, so an unowned row
// resolves to ("", true, nil) and the guard's admin-only branch applies.
func mirrorPolicyOrgResolver(rbacRepo *repositories.RBACRepository) middleware.ResourceOrgResolver {
	return func(ctx context.Context, id string) (string, bool, error) {
		if rbacRepo == nil {
			return "", false, errors.New("rbac repository not configured")
		}
		policyID, err := uuid.Parse(id)
		if err != nil {
			return "", false, nil
		}
		policy, err := rbacRepo.GetMirrorPolicy(ctx, policyID)
		if err != nil {
			return "", false, err
		}
		if policy == nil {
			return "", false, nil
		}
		if policy.OrganizationID == nil || *policy.OrganizationID == uuid.Nil {
			return "", true, nil
		}
		return policy.OrganizationID.String(), true, nil
	}
}
