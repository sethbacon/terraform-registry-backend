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
// The Swagger UI at /api-docs/ is served from embedded static assets (no CDN
// dependency). A per-request nonce allows the inline initialization script to
// execute while keeping the CSP strict for all other content.
package api

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/api/modules"
	"github.com/terraform-registry/terraform-registry/internal/api/oci"
	"github.com/terraform-registry/terraform-registry/internal/api/setup"
	terraform_binaries "github.com/terraform-registry/terraform-registry/internal/api/terraform_binaries"
	"github.com/terraform-registry/terraform-registry/internal/api/webhooks"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/auth/mtls"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
	"github.com/terraform-registry/terraform-registry/internal/policy"
	"github.com/terraform-registry/terraform-registry/internal/scm"
	"github.com/terraform-registry/terraform-registry/internal/scm/appcreds"
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
	// jobs holds every background job behind the jobs.Job interface so they
	// start and stop uniformly (issue #565 finding [40]) instead of via a
	// hand-maintained field-per-job list.
	jobs               *jobs.Registry
	rateLimiters       []middleware.RateLimiterBackend
	principalOverrides *middleware.PrincipalOverrideLimiters
}

// Shutdown stops all background goroutines. It should be called after the HTTP
// server has been shut down so that in-flight requests are drained first.
// coverage:skip:integration-only — requires a running router with live DB and jobs
func (bg *BackgroundServices) Shutdown() {
	slog.Info("stopping background services")
	if bg.jobs != nil {
		bg.jobs.StopAll()
	}
	for _, rl := range bg.rateLimiters {
		if rl != nil {
			_ = rl.Close()
		}
	}
	if bg.principalOverrides != nil {
		_ = bg.principalOverrides.Close()
	}
	slog.Info("all background services stopped")
}

// collectRateLimiterBackends returns a slice of non-nil rate limiter backends for shutdown tracking.
func collectRateLimiterBackends(backends ...middleware.RateLimiterBackend) []middleware.RateLimiterBackend {
	var out []middleware.RateLimiterBackend
	for _, b := range backends {
		if b != nil {
			out = append(out, b)
		}
	}
	return out
}

// AppVersion, AppBuildDate, and AppCryptoMode are set by main before NewRouter
// is called. They are populated from ldflags injected by GoReleaser at release time.
var AppVersion = "dev"
var AppBuildDate = "unknown"
var AppCryptoMode = "standard"

// NewRouter creates and configures the Gin router.
// coverage:skip:integration-only — wires all repos, jobs, and services together; tested via E2E
// identityDB backs identity data access (users, organizations, API keys, OIDC
// config, audit logs, role templates, revoked tokens). It equals db unless the
// identity-schema cutover is enabled, in which case it targets the shared
// identity schema (feature tables fall back to public via search_path).
func NewRouter(cfg *config.Config, db, identityDB *sql.DB) (*gin.Engine, *BackgroundServices) {
	router := gin.New()
	if err := router.SetTrustedProxies(cfg.Server.TrustedProxies); err != nil {
		log.Fatalf("invalid trusted_proxies config: %v", err)
	}

	// egressGuard widens the SSRF deny-list enforced by every outbound client
	// this router wires up (mirror sync, SCM connectors, OSV poller, policy
	// bundle, SAML metadata, ...) per security.egress.allowlist. Config.Validate
	// already parsed this list once at Load(); a second parse error here would
	// mean cfg was constructed without going through config.Load.
	egressGuard, err := httpsafe.NewGuard(cfg.Security.Egress.Allowlist)
	if err != nil {
		log.Fatalf("invalid security.egress.allowlist: %v", err)
	}
	if err := scm.ConfigureEgress(cfg.Security.Egress.Allowlist); err != nil {
		log.Fatalf("failed to configure SCM connector egress policy: %v", err)
	}

	// Initialize storage backend
	storageBackend, err := storage.NewStorage(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize storage backend: %v", err)
	}
	log.Printf("Initialized storage backend: %s", cfg.Storage.DefaultBackend)

	// Identity repositories use identityDB so they follow the configured identity
	// schema; feature repositories below stay on db (public schema).
	userRepo := repositories.NewUserRepository(identityDB)
	apiKeyRepo := repositories.NewAPIKeyRepository(identityDB)
	moduleRepo := repositories.NewModuleRepository(db)
	providerRepo := repositories.NewProviderRepository(db)
	auditRepo := repositories.NewAuditRepository(identityDB)
	orgRepo := repositories.NewOrganizationRepository(identityDB)
	tokenRepo := repositories.NewTokenRepository(identityDB)
	// userTokenRevocationRepo lives on the registry's own domain connection
	// (not identityDB) since it has no FK dependency on the identity schema and
	// must work unchanged whether identity data is in the app's public schema,
	// the shared identity schema, or a separate identity database (issue #559
	// finding [9]).
	userTokenRevocationRepo := repositories.NewUserTokenRevocationRepository(db)

	// Namespace ownership claims back the object-level authorization on every
	// module/provider mutation route (issue #555, CWE-639): a namespace binds
	// to the organization that first publishes into it, and only principals
	// with write access in that organization (or admins) may mutate its
	// artifacts. The authorizer is wired per-route below, after RequireScope.
	nsClaimRepo := repositories.NewNamespaceClaimRepository(db)
	nsAuthz := middleware.NewNamespaceAuthorizer(orgRepo, nsClaimRepo, moduleRepo, providerRepo)

	// Wrap *sql.DB with sqlx for SCM and mirror repositories (public) and identity
	// data access (the identity schema when the cutover is enabled).
	sqlxDB := sqlx.NewDb(db, "postgres")
	identitySqlxDB := sqlx.NewDb(identityDB, "postgres")
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	mirrorRepo := repositories.NewMirrorRepository(sqlxDB)
	storageConfigRepo := repositories.NewStorageConfigRepository(sqlxDB)
	// OIDC-config CRUD follows the identity schema; setup-wizard state stays public.
	oidcConfigRepo := repositories.NewOIDCConfigRepositoryWithIdentity(sqlxDB, identitySqlxDB)

	providerDocsRepo := repositories.NewProviderDocsRepository(db)
	scanRepo := repositories.NewModuleScanRepository(db)
	moduleDocsRepo := repositories.NewModuleDocsRepository(db)

	// Initialize pull-through caching service
	pullThroughSvc := services.NewPullThroughService(providerRepo, mirrorRepo, orgRepo)
	pullThroughSvc.SetEgressGuard(egressGuard)

	// jobRegistry collects every background job; they are all started together
	// via StartAll near the end of NewRouter (after full wiring) and stopped
	// together by BackgroundServices.Shutdown (issue #565 finding [40]).
	jobRegistry := jobs.NewRegistry()

	// Initialize mirror sync job - checks every 10 minutes for mirrors needing sync.
	mirrorSyncJob := jobs.NewMirrorSyncJob(mirrorRepo, providerRepo, providerDocsRepo, orgRepo, storageBackend, cfg.Storage.DefaultBackend)
	mirrorSyncJob.SetApprovalRepo(repositories.NewVersionApprovalRepository(sqlxDB))
	mirrorSyncJob.SetEgressGuard(egressGuard)
	mirrorSyncJob.SetInterval(10)
	jobRegistry.Register(mirrorSyncJob)

	// Initialize Terraform binary mirror repository and sync job
	tfMirrorRepo := repositories.NewTerraformMirrorRepository(sqlxDB)
	tfMirrorSyncJob := jobs.NewTerraformMirrorSyncJob(tfMirrorRepo, storageBackend, cfg.Storage.DefaultBackend)
	tfMirrorSyncJob.SetEgressGuard(egressGuard)
	tfMirrorSyncJob.SetInterval(10)
	jobRegistry.Register(tfMirrorSyncJob)

	// Initialize and start the upstream release-signing GPG key refresh job.
	// On success it installs itself as the in-process resolver consulted by
	// terraform mirror sync, so the next sync tick after a successful refresh
	// uses the cached upstream key instead of the embedded snapshot.
	releasesKeyRepo := repositories.NewReleasesGPGKeyRepository(sqlxDB)
	releasesKeyHTTPClient := httpsafe.NewClient(30*time.Second, egressGuard)
	releasesKeyRefreshJob, releasesKeyJobErr := jobs.NewReleasesKeyRefreshJob(&cfg.ReleasesGPGKeys, releasesKeyRepo, releasesKeyHTTPClient)
	if releasesKeyJobErr != nil {
		// The only way construction fails is a parse error on the embedded
		// OpenTofu snapshot — fatal because the fingerprint pin can't be
		// derived. Log and continue without auto-refresh; the embedded
		// fallback still works.
		log.Printf("Releases key refresh job: construction failed: %v (auto-refresh disabled)", releasesKeyJobErr)
	} else {
		jobs.SetReleasesKeyResolver(releasesKeyRefreshJob)
		jobRegistry.Register(releasesKeyRefreshJob)
	}

	// Public handler is created here (before route registration)
	tfBinariesHandler := terraform_binaries.NewHandler(tfMirrorRepo, storageBackend, auditRepo)

	// OCI distribution handler (public read, backed by existing module storage)
	ociHandler := oci.NewHandler(db, storageBackend)

	// Initialize the API key expiry notifier
	expiryNotifier := jobs.NewAPIKeyExpiryNotifier(apiKeyRepo, userRepo, &cfg.Notifications)
	jobRegistry.Register(expiryNotifier)

	// Apply any scanning configuration persisted by the setup wizard (over the
	// file/env config) before constructing the scanner job, which reads
	// cfg.Scanning at build time. See reloadScanningConfigFromDB.
	reloadScanningConfigFromDB(cfg, oidcConfigRepo)

	moduleScannerJob := jobs.NewModuleScannerJob(&cfg.Scanning, scanRepo, moduleRepo, storageBackend)
	jobRegistry.Register(moduleScannerJob)

	// Initialize and start the scheduled scanner update-check job (no-op when
	// scanning.auto_update.enabled=false). Discovers newer upstream scanner
	// releases, files them into the version-approval workflow, and reconciles
	// approved-but-inactive versions into the running scanner.
	sbvRepo := repositories.NewScannerBinaryVersionRepository(sqlxDB)
	scannerApprovalRepo := repositories.NewVersionApprovalRepository(sqlxDB)
	scannerUpdateJob := jobs.NewScannerUpdateJob(&cfg.Scanning, &cfg.Notifications, &cfg.CVE, sbvRepo, scannerApprovalRepo, oidcConfigRepo, moduleScannerJob, nil, nil)
	jobRegistry.Register(scannerUpdateJob)

	// Initialize the audit log cleanup job (no-op when retention_days=0)
	auditCleanupJob := jobs.NewAuditCleanupJob(&cfg.AuditRetention, auditRepo)
	jobRegistry.Register(auditCleanupJob)

	// Get encryption key from environment for OAuth token encryption
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		log.Fatal("ENCRYPTION_KEY environment variable must be set for SCM integration")
	}
	// ENCRYPTION_KEY is used directly as raw AES-256 key bytes (no KDF/hashing), so its
	// real-world entropy determines the actual strength of the cipher. This is a
	// heuristic warning only — it cannot prove or disprove true randomness — for
	// operators who set ENCRYPTION_KEY to a human-typed passphrase instead of following
	// the documented `openssl rand -hex 16` generation method (see docs/secrets-rotation.md).
	if crypto.IsLikelyLowEntropySecret([]byte(encryptionKey)) {
		log.Printf("WARNING: ENCRYPTION_KEY has low estimated entropy and may not have been generated with a CSPRNG. Generate one with: openssl rand -hex 16")
	}
	encryptionKeyPrevious := os.Getenv("ENCRYPTION_KEY_PREVIOUS")

	// Initialize token cipher for encrypting OAuth tokens.
	// When ENCRYPTION_KEY_PREVIOUS is set, the cipher supports dual-key
	// decryption for zero-downtime key rotation.
	var tokenCipher *crypto.TokenCipher
	if encryptionKeyPrevious != "" {
		tokenCipher, err = crypto.NewTokenCipherWithPrevious([]byte(encryptionKey), []byte(encryptionKeyPrevious))
		if err != nil {
			log.Fatalf("Failed to initialize dual-key token cipher: %v", err)
		}
		slog.Info("token cipher initialized with previous key for rotation support")
	} else {
		tokenCipher, err = crypto.NewTokenCipher([]byte(encryptionKey))
		if err != nil {
			log.Fatalf("Failed to initialize token cipher: %v", err)
		}
	}

	// Reload persisted notifications config from the database (if present),
	// applying it on top of the YAML/env defaults. Must run after tokenCipher
	// is constructed since the stored SMTP password is encrypted. See
	// reloadNotificationsConfigFromDB.
	reloadNotificationsConfigFromDB(cfg, oidcConfigRepo, tokenCipher)

	// Add middleware
	router.Use(gin.Recovery())
	router.Use(middleware.RequestIDMiddleware())
	router.Use(middleware.MetricsMiddleware())
	router.Use(LoggerMiddleware(cfg))
	router.Use(CORSMiddleware(cfg))
	router.Use(middleware.SecurityHeadersMiddleware(middleware.APISecurityHeadersConfig()))

	// mTLS client-certificate authentication (issue #559 finding [3]). Registered
	// globally and before the per-route Auth/OptionalAuth middleware groups
	// below, so a verified client cert's mapped scopes are already in the Gin
	// context by the time those run — AuthMiddleware treats auth_method=="mtls"
	// as satisfying its "credentials present" check even with no bearer token.
	// Actually verifying and surfacing the client cert requires the TLS server
	// itself to request+verify one (see mtls.BuildServerTLSConfig, wired in
	// cmd/server/main.go); nothing here works over plain HTTP or behind a
	// TLS-terminating ingress.
	if cfg.Security.MTLS.Enabled {
		mtlsProvider, mtlsErr := mtls.NewProvider(cfg.Security.MTLS)
		if mtlsErr != nil {
			log.Fatalf("failed to initialize mTLS provider: %v", mtlsErr)
		}
		router.Use(mtls.AuthMiddleware(mtlsProvider))
	}

	// Public + Terraform-protocol routes (issue #565 finding [39]). See registerPublicRoutes.
	registerPublicRoutes(router, &publicRouteDeps{
		cfg:                     cfg,
		db:                      db,
		storageBackend:          storageBackend,
		ociHandler:              ociHandler,
		userRepo:                userRepo,
		apiKeyRepo:              apiKeyRepo,
		orgRepo:                 orgRepo,
		tokenRepo:               tokenRepo,
		userTokenRevocationRepo: userTokenRevocationRepo,
		auditRepo:               auditRepo,
		pullThroughSvc:          pullThroughSvc,
		tfBinariesHandler:       tfBinariesHandler,
	})

	// Initialize admin handlers
	// Select OIDC state store backend: Redis for HA, in-memory for single-instance.
	var oidcStateStore auth.StateStore
	if cfg.Redis.Host != "" {
		redisStore, storeErr := auth.NewRedisStateStore(&cfg.Redis)
		if storeErr != nil {
			slog.Warn("failed to create Redis OIDC state store, falling back to in-memory", "error", storeErr)
			oidcStateStore = auth.NewMemoryStateStore(5 * time.Minute)
		} else {
			oidcStateStore = redisStore
		}
	} else {
		oidcStateStore = auth.NewMemoryStateStore(5 * time.Minute)
	}

	var authHandlers *admin.AuthHandlers
	authHandlers, err = admin.NewAuthHandlers(cfg, identityDB, oidcConfigRepo, tokenRepo, oidcStateStore, admin.WithSAMLEgressGuard(egressGuard))
	if err != nil {
		log.Fatalf("Failed to initialize auth handlers: %v", err)
	}

	// Load OIDC configuration persisted by the setup wizard from the database
	// (takes precedence over static config-file settings). See
	// applyPersistedOIDCProvider.
	applyPersistedOIDCProvider(authHandlers, oidcConfigRepo, tokenCipher)

	// Identity-backed admin handlers use the identity connection (their internal
	// identity repos / raw identity SQL then follow the identity schema). The org
	// handler's namespace cascade and the stats handler's feature-table counts
	// fall back to public via the identity connection's search_path.
	apiKeyHandlers := admin.NewAPIKeyHandlers(cfg, identityDB)
	userHandlers := admin.NewUserHandlers(cfg, identityDB)
	orgHandlers := admin.NewOrganizationHandlers(cfg, identityDB, nsClaimRepo, userTokenRevocationRepo)
	statsHandlers := admin.NewStatsHandler(identitySqlxDB, &cfg.Scanning)
	mirrorHandlers := admin.NewMirrorHandler(mirrorRepo, orgRepo, providerRepo)
	mirrorHandlers.SetSyncJob(mirrorSyncJob) // Connect sync job for manual triggers
	mirrorHandlers.SetEgressGuard(egressGuard)

	// Initialize Terraform binary mirror admin handler
	tfMirrorAdminHandler := admin.NewTerraformMirrorHandler(tfMirrorRepo)
	tfMirrorAdminHandler.SetSyncJob(tfMirrorSyncJob)
	tfMirrorAdminHandler.SetStorageBackend(storageBackend) // delete stored binaries when a version is removed
	tfMirrorAdminHandler.SetEgressGuard(egressGuard)
	releasesGPGKeysAdminHandler := admin.NewReleasesGPGKeysHandler(releasesKeyRepo, tfMirrorRepo, cfg.ReleasesGPGKeys)
	versionApprovalHandler := admin.NewVersionApprovalHandler(repositories.NewVersionApprovalRepository(sqlxDB))
	providerAdminHandlers := admin.NewProviderAdminHandlers(db, storageBackend, cfg)
	moduleAdminHandlers := admin.NewModuleAdminHandlers(db, storageBackend, cfg).
		WithModuleDocs(moduleDocsRepo).
		WithScanQueue(scanRepo)

	// GDPR data-subject handlers (Article 15/17/20). Registered under
	// /api/v1/admin/users/:id/{export,erase} below.
	userSvc := services.NewUserService(identityDB)
	gdprHandlers := admin.NewGDPRHandlers(userSvc)

	// Role-template CRUD follows the identity schema; mirror methods stay public.
	rbacRepo := repositories.NewRBACRepositoryWithIdentity(sqlxDB, identitySqlxDB)
	rbacHandlers := admin.NewRBACHandlers(rbacRepo, userTokenRevocationRepo)

	// Initialize audit log handlers
	auditLogHandlers := admin.NewAuditLogHandlers(identityDB)

	// Shared app-credential minter (Entra app / GitHub App) for providers opted
	// into an app auth mode; scmRepo provides the token-cache store.
	sharedMinter := appcreds.NewMinter(tokenCipher, scmRepo)

	// Initialize SCM publisher service (needed by scmLinkingHandler)
	scmPublisher := services.NewSCMPublisher(scmRepo, moduleRepo, storageBackend, tokenCipher).
		WithScanQueue(scanRepo, &cfg.Scanning).
		WithModuleDocs(moduleDocsRepo).
		WithSharedMinter(sharedMinter)

	// Initialize the webhook retry job (no-op when max_retries=0)
	webhookRetryJob := jobs.NewWebhookRetryJob(&cfg.Webhooks, scmRepo, moduleRepo, scmPublisher, tokenCipher)
	jobRegistry.Register(webhookRetryJob)

	// Initialize the CVE polling job (no-op when cve.enabled=false)
	cveRepo := repositories.NewCVERepository(db)
	cvePollJob := jobs.NewCVEPollJob(cveRepo, auditRepo, &cfg.Scanning, &cfg.CVE, &cfg.Notifications)
	cvePollJob.SetEgressGuard(egressGuard)
	jobRegistry.Register(cvePollJob)

	// Initialize SCM handlers with the already-created repositories and token cipher
	scmProviderHandlers := admin.NewSCMProviderHandlers(cfg, scmRepo, orgRepo, tokenCipher).WithMinter(sharedMinter).WithEgressGuard(egressGuard)
	scmOAuthHandlers := admin.NewSCMOAuthHandlers(cfg, scmRepo, userRepo, tokenCipher).WithMinter(sharedMinter)
	scmLinkingHandler := modules.NewSCMLinkingHandler(scmRepo, moduleRepo, tokenCipher, cfg.Server.BaseURL, scmPublisher).WithMinter(sharedMinter)

	// Initialize storage configuration handlers
	storageHandlers := admin.NewStorageHandlers(cfg, storageConfigRepo, tokenCipher)

	// Initialize notifications configuration handlers
	notificationsHandler := admin.NewNotificationsHandler(&cfg.Notifications, oidcConfigRepo, tokenCipher, &cfg.CVE)

	// Initialize OIDC admin configuration handlers
	oidcAdminHandlers := admin.NewOIDCConfigAdminHandlers(oidcConfigRepo)

	// Initialize setup wizard handlers
	setupHandlers := setup.NewHandlers(
		cfg, tokenCipher, oidcConfigRepo, storageConfigRepo, userRepo, orgRepo, authHandlers,
	).WithScannerJob(moduleScannerJob)

	// Initialize policy engine (no-op when disabled).
	policyEngineCfg := policy.Config{
		Enabled:               cfg.Policy.Enabled,
		Mode:                  cfg.Policy.Mode,
		BundleURL:             cfg.Policy.BundleURL,
		BundleSHA256:          cfg.Policy.BundleSHA256,
		BundleRefreshInterval: cfg.Policy.BundleRefreshInterval,
	}
	policyEngine, err := policy.NewPolicyEngineWithGuard(policyEngineCfg, egressGuard)
	if err != nil {
		log.Fatalf("failed to initialize policy engine: %v", err)
	}
	policyAdminHandler := admin.NewPolicyHandler(policyEngine, cfg.Policy)

	// Initialize SCM webhook handler
	scmWebhookHandler := webhooks.NewSCMWebhookHandler(scmRepo, scmPublisher, tokenCipher)
	approvalWebhookHandler := webhooks.NewApprovalHandler(rbacRepo)

	// Initialize rate limiters (conditionally, based on config)
	var authRateLimiter, generalRateLimiter, uploadRateLimiter middleware.RateLimiterBackend
	var orgRateLimiter middleware.RateLimiterBackend
	if cfg.Security.RateLimiting.Enabled {
		// Build effective configs: use config values when set, otherwise fall back to presets
		generalCfg := middleware.DefaultRateLimitConfig()
		if cfg.Security.RateLimiting.RequestsPerMinute > 0 {
			generalCfg.RequestsPerMinute = cfg.Security.RateLimiting.RequestsPerMinute
		}
		if cfg.Security.RateLimiting.Burst > 0 {
			generalCfg.BurstSize = cfg.Security.RateLimiting.Burst
		}
		authCfg := middleware.AuthRateLimitConfig()
		uploadCfg := middleware.UploadRateLimitConfig()

		if cfg.Redis.Host != "" {
			// Redis-backed rate limiters for HA deployments
			var redisErr error
			generalRateLimiter, redisErr = middleware.NewRedisRateLimiter(&cfg.Redis, generalCfg)
			if redisErr != nil {
				slog.Warn("failed to create Redis rate limiter for general, falling back to in-memory", "error", redisErr)
				generalRateLimiter = middleware.NewRateLimiter(generalCfg)
			}
			authRateLimiter, redisErr = middleware.NewRedisRateLimiter(&cfg.Redis, authCfg)
			if redisErr != nil {
				slog.Warn("failed to create Redis rate limiter for auth, falling back to in-memory", "error", redisErr)
				authRateLimiter = middleware.NewRateLimiter(authCfg)
			}
			uploadRateLimiter, redisErr = middleware.NewRedisRateLimiter(&cfg.Redis, uploadCfg)
			if redisErr != nil {
				slog.Warn("failed to create Redis rate limiter for upload, falling back to in-memory", "error", redisErr)
				uploadRateLimiter = middleware.NewRateLimiter(uploadCfg)
			}
			// Per-organization rate limiter (only when configured)
			if cfg.Security.RateLimiting.OrgRequestsPerMinute > 0 {
				orgCfg := middleware.RateLimitConfig{
					RequestsPerMinute: cfg.Security.RateLimiting.OrgRequestsPerMinute,
					BurstSize:         cfg.Security.RateLimiting.OrgBurst,
					CleanupInterval:   5 * time.Minute,
				}
				if orgCfg.BurstSize == 0 {
					orgCfg.BurstSize = orgCfg.RequestsPerMinute / 4
				}
				orgRateLimiter, redisErr = middleware.NewRedisRateLimiter(&cfg.Redis, orgCfg)
				if redisErr != nil {
					slog.Warn("failed to create Redis org rate limiter, falling back to in-memory", "error", redisErr)
					orgRateLimiter = middleware.NewRateLimiter(orgCfg)
				}
			}
			log.Println("Rate limiting enabled with Redis backend")
		} else {
			// In-memory rate limiters (single-instance only)
			slog.Warn("redis.host not configured: rate limiting will use in-memory backend (not suitable for multi-pod HA)")
			generalRateLimiter = middleware.NewRateLimiter(generalCfg)
			authRateLimiter = middleware.NewRateLimiter(authCfg)
			uploadRateLimiter = middleware.NewRateLimiter(uploadCfg)
			// Per-organization rate limiter
			if cfg.Security.RateLimiting.OrgRequestsPerMinute > 0 {
				orgCfg := middleware.RateLimitConfig{
					RequestsPerMinute: cfg.Security.RateLimiting.OrgRequestsPerMinute,
					BurstSize:         cfg.Security.RateLimiting.OrgBurst,
					CleanupInterval:   5 * time.Minute,
				}
				if orgCfg.BurstSize == 0 {
					orgCfg.BurstSize = orgCfg.RequestsPerMinute / 4
				}
				orgRateLimiter = middleware.NewRateLimiter(orgCfg)
			}
		}
	}

	// Build per-principal override rate limiters (if configured)
	var principalOverrides *middleware.PrincipalOverrideLimiters
	if len(cfg.Security.RateLimiting.PrincipalOverrides) > 0 {
		principalOverrides = middleware.NewPrincipalOverrideLimiters(cfg.Security.RateLimiting.PrincipalOverrides)
		slog.Info("per-principal rate limit overrides configured", "count", len(cfg.Security.RateLimiting.PrincipalOverrides))
	}

	// Public + admin API routes (issue #565 finding [39]). See registerAPIV1Routes.
	registerAPIV1Routes(router, &apiV1RouteDeps{
		cfg:                         cfg,
		db:                          db,
		storageBackend:              storageBackend,
		sqlxDB:                      sqlxDB,
		oidcConfigRepo:              oidcConfigRepo,
		setupHandlers:               setupHandlers,
		authRateLimiter:             authRateLimiter,
		generalRateLimiter:          generalRateLimiter,
		uploadRateLimiter:           uploadRateLimiter,
		orgRateLimiter:              orgRateLimiter,
		principalOverrides:          principalOverrides,
		authHandlers:                authHandlers,
		userRepo:                    userRepo,
		apiKeyRepo:                  apiKeyRepo,
		orgRepo:                     orgRepo,
		tokenRepo:                   tokenRepo,
		userTokenRevocationRepo:     userTokenRevocationRepo,
		moduleAdminHandlers:         moduleAdminHandlers,
		providerAdminHandlers:       providerAdminHandlers,
		auditRepo:                   auditRepo,
		nsAuthz:                     nsAuthz,
		scanRepo:                    scanRepo,
		moduleDocsRepo:              moduleDocsRepo,
		policyEngine:                policyEngine,
		sbvRepo:                     sbvRepo,
		scannerApprovalRepo:         scannerApprovalRepo,
		scannerUpdateJob:            scannerUpdateJob,
		notificationsHandler:        notificationsHandler,
		apiKeyHandlers:              apiKeyHandlers,
		userHandlers:                userHandlers,
		gdprHandlers:                gdprHandlers,
		orgHandlers:                 orgHandlers,
		scmProviderHandlers:         scmProviderHandlers,
		scmOAuthHandlers:            scmOAuthHandlers,
		scmLinkingHandler:           scmLinkingHandler,
		mirrorHandlers:              mirrorHandlers,
		tfMirrorAdminHandler:        tfMirrorAdminHandler,
		releasesGPGKeysAdminHandler: releasesGPGKeysAdminHandler,
		rbacHandlers:                rbacHandlers,
		versionApprovalHandler:      versionApprovalHandler,
		storageHandlers:             storageHandlers,
		storageConfigRepo:           storageConfigRepo,
		moduleRepo:                  moduleRepo,
		providerRepo:                providerRepo,
		tokenCipher:                 tokenCipher,
		oidcAdminHandlers:           oidcAdminHandlers,
		auditLogHandlers:            auditLogHandlers,
		policyAdminHandler:          policyAdminHandler,
		cvePollJob:                  cvePollJob,
		statsHandlers:               statsHandlers,
		scmWebhookHandler:           scmWebhookHandler,
		approvalWebhookHandler:      approvalWebhookHandler,
	})

	// Start every registered background job now that all wiring is complete.
	// Each runs in its own goroutine (Registry.StartAll); context.Background()
	// means they exit only via BackgroundServices.Shutdown (Stop), matching the
	// prior per-job `go job.Start(context.Background())` behavior.
	jobRegistry.StartAll(context.Background())

	bg := &BackgroundServices{
		jobs:               jobRegistry,
		rateLimiters:       collectRateLimiterBackends(authRateLimiter, generalRateLimiter, uploadRateLimiter, orgRateLimiter),
		principalOverrides: principalOverrides,
	}

	return router, bg
}

// @Summary      Health check
// @Description  Returns the health status of the service, including database connectivity.
// @Tags         System
// @Produce      json
// @Success      200  {object}  api.HealthResponse
// @Failure      503  {object}  api.HealthResponse
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
			"status":     "healthy",
			"time":       time.Now().UTC().Format(time.RFC3339),
			"version":    AppVersion,
			"build_date": AppBuildDate,
		})
	}
}

// @Summary      Readiness check
// @Description  Returns whether the service is ready to accept traffic. Checks database connectivity.
// @Tags         System
// @Produce      json
// @Success      200  {object}  api.ReadinessResponse
// @Failure      503  {object}  api.ReadinessResponse
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
// @Success      200  {object}  api.ServiceDiscoveryResponse
// @Router       /.well-known/terraform.json [get]
// serviceDiscoveryHandler implements Terraform service discovery.
//
// The endpoint URLs are built from GetPublicURL() (public_url, falling back to
// base_url) rather than base_url directly. This is the host Terraform resolves
// "source = HOST/ns/name/system" against and that the State Manager captures for
// the suite "Consumed by" join, so it must match the join key the suite proxy
// emits (also GetPublicURL-derived). In the default deploy public_url is empty
// and this is byte-for-byte identical to the previous base_url output.
func serviceDiscoveryHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		publicURL := cfg.Server.GetPublicURL()
		c.JSON(http.StatusOK, gin.H{
			"modules.v1":   publicURL + "/v1/modules/",
			"providers.v1": publicURL + "/v1/providers/",
			"oci.v1":       publicURL + "/v2/",
		})
	}
}

// @Summary      API version
// @Description  Returns the current API version and supported protocol versions.
// @Tags         System
// @Produce      json
// @Success      200  {object}  api.VersionResponse
// @Router       /version [get]
// versionHandler returns the API version
func versionHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":          AppVersion,
			"build_date":       AppBuildDate,
			"api_version":      "v1",
			"crypto_mode":      AppCryptoMode,
			"default_language": cfg.Server.DefaultLanguage,
			"protocols": gin.H{
				"modules":   "v1",
				"providers": "v1",
				"mirror":    "v1",
			},
			"capabilities": gin.H{
				"oci": true,
			},
		})
	}
}

// LoggerMiddleware provides structured logging
func LoggerMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := redactSensitivePath(c.Request.URL.Path)
		query := redactSensitiveQuery(c.Request.URL.RawQuery)

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

		// Check if origin is allowed and track which rule matched
		allowed := false
		matchedWildcard := false
		for _, allowedOrigin := range cfg.Security.CORS.AllowedOrigins {
			if allowedOrigin == "*" {
				allowed = true
				matchedWildcard = true
				break
			}
			if allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			if origin == "" {
				// No Origin header — return wildcard, no credentials
				c.Header("Access-Control-Allow-Origin", "*")
			} else if matchedWildcard {
				// Wildcard config but specific origin present —
				// reflect origin WITHOUT credentials (safer than true wildcard)
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			} else {
				// Specific origin match — credentials allowed
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Credentials", "true")
				c.Header("Vary", "Origin")
			}
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
