// @title           Terraform Registry API
// @version         1.0.0
// @description     Complete Terraform Module and Provider Registry with SCM integration, mirrors, and storage backends
// @termsOfService  https://your-registry.example.com/terms
// @contact.name    Registry Support
// @contact.email   admin@your-registry.example.com
// @license.name    Apache-2.0
// @basePath        /
// @schemes         http https
// @securityDefinitions.apiKey  Bearer
// @in                          header
// @name                        Authorization
// @description                 JWT token or API key. For JWT: 'Bearer {token}'. For API key: 'Bearer {api_key}'
//
// @securityDefinitions.apiKey  SetupToken
// @in                          header
// @name                        X-Setup-Token
// @description                 One-time setup token, valid until /api/v1/setup/complete is called.
//
// @tag.name         System
// @tag.description  Health, readiness, and service-discovery endpoints.
//
// @tag.name         Security Scanning
// @tag.description  Module security scanning configuration, status, and scan results.
//
// @tag.name         Observability
// @tag.description  Prometheus metrics and profiling are served on a dedicated side-channel port (default: 9090) that is separate from the main API server. This keeps the scrape path off the public ingress and avoids rate-limiting middleware. Configure the port with TFR_TELEMETRY_METRICS_PROMETHEUS_PORT. The endpoint path is always GET /metrics. pprof (if enabled via TFR_TELEMETRY_PROFILING_ENABLED=true) is served on TFR_TELEMETRY_PROFILING_PORT (default: 6060) at the standard /debug/pprof/ paths. Neither endpoint is part of the OpenAPI spec because they are not served by the Gin router.

// Package main is the entry point for the Terraform Registry server binary.
// It dispatches subcommands — serve, migrate, version, upgrade, and scan-worker —
// via a simple switch on os.Args so the binary's full CLI surface is readable in
// one place without requiring a cobra dependency. The serve command runs
// auto-migration on startup so freshly deployed containers never need a separate
// migration step. The scan-worker command runs only the module security scanner
// loop so scanning can scale horizontally on dedicated pods.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof" // #nosec G108 -- pprof is NOT served on the main API listener (Gin router).

	// It only serves on a dedicated internal port when cfg.Telemetry.Profiling.Enabled=true.
	// DefaultServeMux is never passed to the Gin HTTP server.
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sethbacon/terraform-suite-identity/identity"
	"github.com/terraform-registry/terraform-registry/internal/api"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/auth/mtls"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
	"github.com/terraform-registry/terraform-registry/internal/storage"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
	"golang.org/x/crypto/bcrypt"
)

// Version, BuildDate, and CryptoMode are injected at build time by GoReleaser via ldflags:
//
//	-X main.Version=x.y.z  -X main.BuildDate=<RFC3339>  -X main.CryptoMode=fips
var Version = "dev"
var BuildDate = "unknown"
var CryptoMode = "standard"

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

func run() error {
	// Parse command from args
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Execute command
	switch command {
	case "serve":
		api.AppVersion = Version
		api.AppBuildDate = BuildDate
		api.AppCryptoMode = CryptoMode
		return serve(cfg)
	case "migrate":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: %s migrate <up|down>", os.Args[0])
		}
		return runMigrations(cfg, os.Args[2])
	case "version":
		fmt.Printf("Terraform Registry v%s (built %s)\n", Version, BuildDate)
		return nil
	case "upgrade":
		return runUpgrade(configPath)
	case "scan-worker":
		return scanWorker(cfg)
	default:
		return fmt.Errorf("unknown command: %s\nAvailable commands: serve, migrate, version, upgrade, scan-worker", command)
	}
}

// runUpgrade dispatches the `upgrade` command's subcommands. Currently only
// `upgrade preflight` is supported, which runs pre-upgrade validation via
// RunUpgradePreflight (see upgrade.go). Flags are parsed from os.Args without a
// cobra dependency to match the rest of the CLI surface.
func runUpgrade(configPath string) error {
	if len(os.Args) < 3 || os.Args[2] != "preflight" {
		return fmt.Errorf("usage: %s upgrade preflight [--config <path>] [--verbose]", os.Args[0])
	}

	// Parse the documented flags. --config overrides the CONFIG_PATH env var;
	// --verbose enables detailed output.
	verbose := false
	args := os.Args[3:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--verbose":
			verbose = true
		case "--config":
			if i+1 >= len(args) {
				return fmt.Errorf("--config requires a path argument")
			}
			configPath = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown flag for 'upgrade preflight': %s", args[i])
		}
	}

	if code := RunUpgradePreflight(configPath, verbose); code != 0 {
		os.Exit(code)
	}
	return nil
}

// scanWorker runs the module security scanner loop as a standalone process,
// decoupled from the API server so scanning can scale horizontally across
// dedicated pods. The API server is expected to run with
// scanning.embedded_worker=false (it still creates pending scans and installs
// scanner binaries via the control plane), while one or more scan-worker
// processes consume the shared module_version_scans queue. Claiming is race-safe
// via an atomic UPDATE, so any number of workers can run concurrently.
//
// Unlike serve(), the worker does NOT run database migrations (the API server
// owns the schema) and does NOT start the HTTP API, metrics endpoint, or
// control-plane jobs. Scanning must be enabled via env/YAML config
// (TFR_SCANNING_*); the worker forces scanning.embedded_worker=true for its own
// process regardless of the API-server setting.
func scanWorker(cfg *config.Config) error {
	telemetry.SetupLogger(cfg.Logging.Format, cfg.Logging.Level)

	// This process IS the scan worker: always run the scanner loop in-process,
	// even when the shared config disables the embedded worker on the API server.
	cfg.Scanning.EmbeddedWorker = true

	if !cfg.Scanning.Enabled {
		slog.Warn("scan-worker: scanning is disabled (scanning.enabled=false); the worker will idle until scanning is enabled via TFR_SCANNING_ENABLED / config")
	}

	// Connect to the database. The worker shares the API server's schema and must
	// NOT run migrations (the API server owns migrations).
	database, err := db.Connect(cfg.Database.GetDSN(), cfg.Database.MaxConnections, cfg.Database.MinIdleConnections)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()
	slog.Info("scan-worker: connected to database")

	storageBackend, err := storage.NewStorage(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize storage backend: %w", err)
	}

	scanRepo := repositories.NewModuleScanRepository(database)
	moduleRepo := repositories.NewModuleRepository(database)
	scannerJob := jobs.NewModuleScannerJob(&cfg.Scanning, scanRepo, moduleRepo, storageBackend)

	// Handle SIGINT/SIGTERM for graceful shutdown (Kubernetes sends SIGTERM on
	// pod termination). Cancelling ctx stops the scanner loop.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("scan-worker: starting", "version", Version, "build_date", BuildDate)

	// Start blocks while the scan loop runs and returns nil early when the scanner
	// is not yet ready (binary missing, version mismatch, or scanning disabled).
	// In the not-ready case, wait and retry so the worker comes online
	// automatically once the control plane installs the scanner binary on the
	// shared volume, rather than crash-looping the pod.
	for {
		if err := scannerJob.Start(ctx); err != nil {
			slog.Error("scan-worker: scanner loop error", "error", err)
		}
		select {
		case <-ctx.Done():
			slog.Info("scan-worker: shutting down")
			return nil
		case <-time.After(30 * time.Second):
			slog.Info("scan-worker: scanner not ready, retrying")
		}
	}
}

func serve(cfg *config.Config) error {
	// Initialise structured logger as early as possible so all subsequent log output
	// uses the configured format (json / text) and level.
	telemetry.SetupLogger(cfg.Logging.Format, cfg.Logging.Level)

	// Export build information as a Prometheus metric so fleet inventory queries
	// can determine which version is deployed where.
	telemetry.AppInfo.WithLabelValues(Version, runtime.Version(), BuildDate).Set(1)

	// Set Gin mode
	// Note: gin.SetMode sets the GIN_MODE env var as a side effect. Ensure
	// jwt.isDevMode() does NOT check GIN_MODE to avoid accidentally enabling
	// dev mode (skipping JWT secret requirement) in production.
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Issue #559 findings [5]/[11]: DEV_MODE unlocks unauthenticated admin-session
	// minting (/api/v1/dev/login, /api/v1/dev/impersonate) gated only by this one
	// environment variable. Defaults closed and also requires a seeded
	// admin@dev.local account, but give operators a loud, unmissable signal if
	// it's ever set, since there is no other startup-time indication.
	devModeEnabled := devModeFromEnv(os.Getenv("DEV_MODE"))
	if devModeEnabled {
		log.Println("WARNING: ==========================================================")
		log.Println("WARNING: DEV_MODE is enabled. Unauthenticated admin-session minting")
		log.Println("WARNING: endpoints (/api/v1/dev/login, /api/v1/dev/impersonate) are")
		log.Println("WARNING: ACTIVE. This must never be set in a production deployment.")
		log.Println("WARNING: ==========================================================")
	}

	// Refuse to boot entirely when DEV_MODE is combined with a production
	// indicator, rather than relying on the warning above being noticed. See
	// devModeProductionGuard's doc comment for why logging.level is the signal.
	if err := devModeProductionGuard(devModeEnabled, cfg.Logging.Level, devModeNonProductionConfirmed()); err != nil {
		return err
	}

	// Validate JWT secret configuration (fails in production if not set)
	if err := auth.ValidateJWTSecret(); err != nil {
		return fmt.Errorf("security configuration error: %w", err)
	}
	log.Println("JWT secret validated successfully")

	// Extend JWT issuer validation to trusted sibling apps in a coupled suite
	// deployment (issue #559 finding [0]). Safe to call unconditionally:
	// with suite.trusted_issuers unset (the default), this re-asserts the same
	// own-issuer-only set ValidateJWTSecret already configured.
	auth.SetTrustedIssuers(cfg.Suite.TrustedIssuers)
	if len(cfg.Suite.TrustedIssuers) > 0 {
		log.Printf("JWT trusted issuers extended for suite coupling: %v", cfg.Suite.TrustedIssuers) // #nosec G706 -- config values from trusted config file/env, not user input
	}

	// Debug: Print database configuration (mask password)
	maskedPassword := "****"
	if cfg.Database.Password != "" {
		maskedPassword = cfg.Database.Password[:1] + "****"
	}
	log.Printf("Database config: host=%s, port=%d, user=%s, password=%s, dbname=%s, sslmode=%s", // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, maskedPassword,
		cfg.Database.Name, cfg.Database.SSLMode)
	log.Printf("Full DSN (masked): %s", cfg.Database.GetDSN()) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input

	// Connect to database
	database, err := db.Connect(cfg.Database.GetDSN(), cfg.Database.MaxConnections, cfg.Database.MinIdleConnections)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	log.Println("Connected to database successfully")

	// Begin exporting DB pool statistics to Prometheus.
	telemetry.StartDBStatsCollector(database)

	// Run identity schema migrations first when enabled (shared identity
	// component, ADR 002). Off by default so production behaviour is unchanged
	// until explicitly enabled; mirrors the TFR_SECURITY_TLS_ENABLED env flag.
	if identityMigrationsEnabled() {
		log.Println("Running identity schema migrations...")
		// Run against the identity database (defaults to the app DB). Identity
		// migrations are schema-qualified (identity.*), so a plain connection
		// suffices; a dedicated connection lets identity live in a separate database
		// (TFR_IDENTITY_DATABASE_*) without coupling to the app pool.
		identityMigrateDB, mErr := db.Connect(
			cfg.IdentityDatabase.GetDSN(),
			cfg.IdentityDatabase.MaxConnections, cfg.IdentityDatabase.MinIdleConnections,
		)
		if mErr != nil {
			return fmt.Errorf("failed to connect to identity database: %w", mErr)
		}
		if err := identity.RunMigrations(identityMigrateDB, "up"); err != nil {
			_ = identityMigrateDB.Close()
			return fmt.Errorf("failed to run identity migrations: %w", err)
		}
		_ = identityMigrateDB.Close()
		log.Println("Identity schema migrations completed successfully")
	}

	// Run migrations automatically on startup
	log.Println("Running database migrations...")
	if err := db.RunMigrations(database, "up"); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}
	log.Println("Database migrations completed successfully")

	// Get migration version
	version, dirty, err := db.GetMigrationVersion(database)
	if err != nil {
		log.Printf("Warning: failed to get migration version: %v", err)
	} else {
		log.Printf("Database schema version: %d (dirty: %v)", version, dirty) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
	}

	// Setup token generation for first-run setup wizard.
	// If setup has not been completed and no token hash exists, generate a
	// cryptographic setup token, print it to logs, and store its bcrypt hash.
	sqlxDB := sqlx.NewDb(database, "postgres")
	oidcConfigRepo := repositories.NewOIDCConfigRepository(sqlxDB)
	if err := handleSetupToken(oidcConfigRepo); err != nil {
		log.Printf("Warning: setup token handling failed: %v", err)
	}

	// Start Prometheus metrics endpoint on a dedicated port so it is not reachable
	// through the public API ingress path.
	if cfg.Telemetry.Metrics.Enabled {
		metricsAddr := fmt.Sprintf(":%d", cfg.Telemetry.Metrics.PrometheusPort)
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			slog.Info("starting Prometheus metrics server", "addr", metricsAddr)
			// Use http.Server with timeouts (G114: bare http.ListenAndServe has no timeout support).
			srv := &http.Server{
				Addr:         metricsAddr,
				Handler:      mux,
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server error", "error", err)
			}
		}()
	}

	// Start pprof endpoint on its own port (disabled in production by default).
	if cfg.Telemetry.Profiling.Enabled {
		pprofAddr := fmt.Sprintf(":%d", cfg.Telemetry.Profiling.Port)
		go func() {
			slog.Info("starting pprof server", "addr", pprofAddr)
			// net/http/pprof registers its handlers on http.DefaultServeMux at init time.
			// Use http.Server with timeouts (G114: bare http.ListenAndServe has no timeout support).
			srv := &http.Server{ //nolint:gosec // #nosec G112 -- internal-only pprof port, long timeouts acceptable
				Addr:         pprofAddr,
				Handler:      http.DefaultServeMux, // #nosec G108 -- not the main listener; pprof-only internal port
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("pprof server error", "error", err)
			}
		}()
	}

	// Determine the connection for identity data access. When the identity-schema
	// cutover is enabled, open a dedicated pool whose search_path resolves identity
	// tables against the shared identity schema (feature tables fall back to
	// public). Otherwise identity data stays in the app's public schema.
	identityDB := database
	if identitySchemaEnabled() {
		searchPath := identitySchemaName() + ",public"
		idb, connErr := db.Connect(
			cfg.IdentityDatabase.GetDSNWithSearchPath(searchPath),
			cfg.IdentityDatabase.MaxConnections, cfg.IdentityDatabase.MinIdleConnections,
		)
		if connErr != nil {
			return fmt.Errorf("failed to connect to identity schema: %w", connErr)
		}
		defer idb.Close()
		identityDB = idb
		slog.Info("identity schema cutover enabled", "search_path", searchPath)

		// The shared identity schema seeds role templates with identity-core
		// scopes only (admin wildcard + cross-cutting reads). Layer the registry's
		// own domain scopes onto the system roles so non-admin roles behave the
		// same as in the default public-schema configuration ("identity-core +
		// app-extended"). Idempotent; no-op on steady-state restarts.
		// Under a shared identity database, exactly one app must own role-template
		// seeding (suite.role_seed_owner) or the apps overwrite each other's role
		// scopes on restart. Default "self" preserves standalone behavior.
		if cfg.Suite.ShouldSeedRoles("registry") {
			if err := repositories.SeedSystemRoleTemplates(
				context.Background(), identityDB, models.PredefinedRoleTemplates(),
			); err != nil {
				return fmt.Errorf("failed to seed system role templates: %w", err)
			}
			slog.Info("system role templates seeded into identity schema")
		} else {
			slog.Info("skipping system role template seeding; another app owns it",
				"role_seed_owner", cfg.Suite.RoleSeedOwner)
		}
	}

	// Create router
	router, bgServices := api.NewRouter(cfg, database, identityDB)

	// Start daily cleanup of expired JWT revocation entries (revoked_tokens is an
	// identity table, so use the identity connection).
	tokenRepo := repositories.NewTokenRepository(identityDB)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := tokenRepo.CleanupExpiredRevocations(context.Background()); err != nil {
				slog.Error("failed to clean up expired token revocations", "error", err)
			}
		}
	}()

	// Start daily cleanup of stale per-user token-revocation watermarks (issue
	// #559 finding [9]; user_token_revocations lives on the registry's own
	// connection, see NewRouter). 25h > the 24h JWT TTL so a watermark is only
	// dropped once every token it could have revoked has expired naturally.
	userRevocationRepo := repositories.NewUserTokenRevocationRepository(database)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := userRevocationRepo.CleanupExpiredWatermarks(context.Background(), 25*time.Hour); err != nil {
				slog.Error("failed to clean up expired user token revocation watermarks", "error", err)
			}
		}
	}()

	// Explicit floor instead of relying on crypto/tls defaults.
	serverTLSConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	// Wire mTLS client-certificate verification into the TLS server (issue #559
	// finding [3]). Without this, the mtls Provider/AuthMiddleware are dead
	// code: c.Request.TLS.VerifiedChains is only ever populated by Go's TLS
	// stack when the server itself requests and verifies a client cert during
	// the handshake, which requires ClientCAs + ClientAuth on this tls.Config.
	if cfg.Security.MTLS.Enabled {
		if !cfg.Security.TLS.Enabled {
			// mTLS is a TLS-handshake-level control; it cannot function unless
			// this process terminates TLS itself. See mtls.BuildServerTLSConfig's
			// doc comment for the TLS-terminating-ingress case, which has the
			// same failure mode (no cfg.Security.TLS.Enabled to check there —
			// this is the in-process version of that warning).
			slog.Warn("security.mtls.enabled is true but security.tls.enabled is false; " +
				"mTLS requires this server to terminate TLS itself and will have no effect " +
				"(client certificates are never requested over plain HTTP)")
		}
		mtlsTLSConfig, mtlsErr := mtls.BuildServerTLSConfig(cfg.Security.MTLS)
		if mtlsErr != nil {
			return fmt.Errorf("mTLS configuration error: %w", mtlsErr)
		}
		serverTLSConfig.ClientCAs = mtlsTLSConfig.ClientCAs
		serverTLSConfig.ClientAuth = mtlsTLSConfig.ClientAuth
		log.Println("mTLS client-certificate verification enabled on the TLS server")
	}

	// Create HTTP server
	server := &http.Server{
		Addr:              cfg.Server.GetAddress(),
		Handler:           router,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		ReadHeaderTimeout: 10 * time.Second,  // Prevents Slowloris attacks
		IdleTimeout:       120 * time.Second, // Close idle keep-alive connections
		TLSConfig:         serverTLSConfig,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on %s", cfg.Server.GetAddress())  // #nosec G706 -- config values from trusted config file/env, not user input
		log.Printf("Base URL: %s", cfg.Server.BaseURL)                // #nosec G706 -- config values from trusted config file/env, not user input
		log.Printf("Storage backend: %s", cfg.Storage.DefaultBackend) // #nosec G706 -- config values from trusted config file/env, not user input
		log.Printf("Multi-tenancy: %v", cfg.MultiTenancy.Enabled)     // #nosec G706 -- config values from trusted config file/env, not user input
		log.Println("Server is ready to accept connections")

		var err error
		if cfg.Security.TLS.Enabled {
			log.Printf("TLS enabled: cert=%s, key=%s", cfg.Security.TLS.CertFile, cfg.Security.TLS.KeyFile) // #nosec G706 -- config values from trusted config file/env, not user input
			err = server.ListenAndServeTLS(cfg.Security.TLS.CertFile, cfg.Security.TLS.KeyFile)
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	// Stop background jobs and rate limiter goroutines
	bgServices.Shutdown()

	log.Println("Server stopped gracefully")
	return nil
}

// handleSetupToken checks if the initial setup wizard needs a setup token and
// generates one if required. The raw token is printed to stdout (and optionally
// written to SETUP_TOKEN_FILE); only the bcrypt hash is stored in the database.
func handleSetupToken(repo *repositories.OIDCConfigRepository) error {
	ctx := context.Background()

	completed, err := repo.IsSetupCompleted(ctx)
	if err != nil {
		return fmt.Errorf("failed to check setup status: %w", err)
	}
	if completed {
		// Check if there are unconfigured features added in later releases
		hasPending, pendingErr := repo.HasPendingFeatureSetup(ctx)
		if pendingErr != nil {
			return fmt.Errorf("failed to check pending feature setup: %w", pendingErr)
		}
		if !hasPending {
			return nil // Setup fully done, nothing to do
		}
		log.Println("Detected unconfigured features added after initial setup.")
	}

	// Check if a token hash already exists (server restarted before setup completed)
	existingHash, err := repo.GetSetupTokenHash(ctx)
	if err != nil {
		return fmt.Errorf("failed to check existing setup token: %w", err)
	}
	if existingHash != "" {
		log.Println("")
		log.Println("══════════════════════════════════════════════════════════════════")
		log.Println("  SETUP REQUIRED: A setup token was previously generated.")
		log.Println("  If you lost it, delete the setup_token_hash from system_settings")
		log.Println("  and restart the server to generate a new one.")
		log.Println("══════════════════════════════════════════════════════════════════")
		log.Println("")
		return nil
	}

	// Generate a cryptographic setup token: 32 random bytes, base64url-encoded
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("failed to generate setup token: %w", err)
	}
	rawToken := "tfr_setup_" + base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(tokenBytes)

	// Bcrypt-hash the token before storing (cost per auth.BcryptCost — see docs/adr/0011)
	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash setup token: %w", err)
	}

	// Store hash in system_settings
	if err := repo.SetSetupTokenHash(ctx, string(hash)); err != nil {
		return fmt.Errorf("failed to store setup token hash: %w", err)
	}

	// Print token to stdout with prominent framing
	separator := strings.Repeat("═", 66)
	log.Println("")
	log.Println(separator)
	log.Println("  INITIAL SETUP REQUIRED")
	log.Println("")
	log.Printf("  Setup Token: %s", rawToken)
	log.Println("")
	log.Println("  Use this token to complete initial setup via:")
	log.Println("    • Browser:  Navigate to https://<your-host>/setup")
	log.Println("    • API:      POST /api/v1/setup/validate-token")
	log.Println("               Authorization: SetupToken <token>")
	log.Println("")
	log.Println("  This token is single-use and will be invalidated after setup.")
	log.Println("  Treat it like a root password — do not share or log externally.")
	log.Println(separator)
	log.Println("")
	// Optionally write token to a file (for container secret mounting).
	// SETUP_TOKEN_FILE is an operator-controlled environment variable. We clean the
	// path and reject any value that contains path-traversal sequences before use.
	if tokenFile := os.Getenv("SETUP_TOKEN_FILE"); tokenFile != "" {
		// Reject paths containing ".." to prevent directory traversal.
		if strings.Contains(filepath.ToSlash(tokenFile), "..") {
			log.Printf("Warning: SETUP_TOKEN_FILE contains path-traversal sequences, ignoring: %s", tokenFile) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
		} else {
			cleanPath := filepath.Clean(tokenFile)
			// #nosec G703 -- path is operator-supplied config, cleaned and traversal-validated above.
			if err := os.WriteFile(cleanPath, []byte(rawToken), 0600); err != nil {
				log.Printf("Warning: failed to write setup token to %s: %v", cleanPath, err) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
			} else {
				log.Printf("Setup token written to %s", cleanPath) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
			}
		}
	}

	// Warn if TLS is disabled during setup (token will be in Authorization header)
	if os.Getenv("TFR_SECURITY_TLS_ENABLED") != "true" {
		log.Println("Warning: TLS is not enabled. The setup token will be transmitted in plaintext.")
		log.Println("         Consider enabling TLS before completing setup.")
	}

	return nil
}

// identityMigrationsEnabled reports whether the shared identity schema migrations
// (terraform-suite-identity, ADR 002) should run. Off by default; enable with
// TFR_IDENTITY_MIGRATIONS_ENABLED=true. Additive and reversible.
func identityMigrationsEnabled() bool {
	return os.Getenv("TFR_IDENTITY_MIGRATIONS_ENABLED") == "true"
}

// devModeFromEnv parses the raw DEV_MODE environment variable value using the
// same "true" or "1" rule as auth.isDevMode and DevModeMiddleware (duplicated
// rather than imported, same rationale as auth.isDevMode: avoiding an import
// cycle / keeping this a pure function of its input for testability).
func devModeFromEnv(raw string) bool {
	return raw == "true" || raw == "1"
}

// isProductionLoggingLevel reports whether level indicates a production
// deployment.
//
// This codebase has no explicit environment/production config flag (no
// TFR_ENV, no NODE_ENV equivalent) — logging.level is the strongest existing
// signal, because it's the one dimension this repo's own deployment manifests
// already vary consistently between environments: docker-compose.prod.yml and
// the kubernetes "production" overlay both set TFR_LOGGING_LEVEL=warn, while
// every dev/test manifest (docker-compose.yml, docker-compose.test.yml, the
// k8s "dev" overlay) either defaults to "info" or explicitly sets "debug" —
// none of them ever set "warn" or "error". Gin's release/debug mode was
// considered too (see the "Set Gin mode" block above) but it collapses to the
// same logging.level=="debug" check and additionally defaults to release mode
// for the *majority* of non-production configs (e.g. the "info"-level dev
// compose stack), so it would false-positive far more often than the logging
// level check below.
func isProductionLoggingLevel(level string) bool {
	return level == "warn" || level == "error"
}

// devModeNonProductionConfirmed reports whether the operator has explicitly
// confirmed a DEV_MODE deployment running above logging.level=="debug" is not
// production. Read directly via env, matching identitySchemaEnabled below,
// rather than threaded through *config.Config -- this is a boot-time-only
// escape hatch, not application configuration.
func devModeNonProductionConfirmed() bool {
	return os.Getenv("TFR_CONFIRM_NON_PRODUCTION") == "true"
}

// devModeProductionGuard refuses to start the server when DEV_MODE is enabled
// outside of an unambiguous dev/test signal (issue #559 findings [5]/[11]).
// DEV_MODE unconditionally exposes the unauthenticated /api/v1/dev/login
// admin-session-minting endpoint (see internal/api/admin/dev.go); the log
// warning above is easy to miss in aggregated production logs, so this makes
// the misconfiguration a hard startup failure instead.
//
// logging.level alone cannot distinguish dev from production: this repo's own
// dev and test compose stacks run at logging.level=="info" (the config
// default), which is indistinguishable from a plausible, deliberate
// production choice -- an earlier version of this guard only blocked
// "warn"/"error" for exactly that reason, which meant the overwhelmingly
// common case (DEV_MODE=true with logging.level left at its "info" default)
// sailed through unblocked. "debug" is the only logging.level this repo's own
// manifests treat as unambiguously non-production; any other level requires
// an explicit TFR_CONFIRM_NON_PRODUCTION=true acknowledgment. Deployments that
// spin up this backend with DEV_MODE=true at a non-debug logging.level (this
// repo's own docker-compose.yml/docker-compose.test.yml, and any downstream
// repo's compose files that do the same) must set that variable.
//
// devModeEnabled, loggingLevel, and nonProductionConfirmed are passed in
// rather than read from os.Getenv/cfg directly so this stays a pure function,
// independently unit-testable against arbitrary inputs.
func devModeProductionGuard(devModeEnabled bool, loggingLevel string, nonProductionConfirmed bool) error {
	if !devModeEnabled || loggingLevel == "debug" || nonProductionConfirmed {
		return nil
	}
	return fmt.Errorf(
		"refusing to start: DEV_MODE is enabled with logging.level=%q, which is not a reliable dev-only signal "+
			"(this repo's own dev/test compose stacks also run at \"info\", the config default). DEV_MODE "+
			"unconditionally exposes the unauthenticated /api/v1/dev/login admin-session-minting endpoint and "+
			"must never run in a production deployment. Unset DEV_MODE, set logging.level to \"debug\", or if "+
			"this really is a non-production deployment set TFR_CONFIRM_NON_PRODUCTION=true to acknowledge it "+
			"explicitly",
		loggingLevel,
	)
}

// identitySchemaEnabled reports whether identity data (users, organizations, API
// keys, OIDC config, audit logs, role templates, revoked tokens) is read/written
// from the dedicated shared identity schema instead of the app's public schema.
// Off by default; enable with TFR_IDENTITY_SCHEMA_ENABLED=true. Requires the
// identity migrations (TFR_IDENTITY_MIGRATIONS_ENABLED) to have run. Reversible.
func identitySchemaEnabled() bool {
	return os.Getenv("TFR_IDENTITY_SCHEMA_ENABLED") == "true"
}

// identitySchemaName returns the identity schema name (default "identity").
func identitySchemaName() string {
	if name := os.Getenv("TFR_IDENTITY_SCHEMA_NAME"); name != "" {
		return name
	}
	return "identity"
}

func runMigrations(cfg *config.Config, direction string) error {
	// Connect to database
	database, err := db.Connect(cfg.Database.GetDSN(), cfg.Database.MaxConnections, cfg.Database.MinIdleConnections)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	log.Printf("Running migrations: %s", direction) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input

	// Apply identity schema migrations first when enabled (ADR 002).
	if identityMigrationsEnabled() {
		if err := identity.RunMigrations(database, direction); err != nil {
			return fmt.Errorf("identity migration failed: %w", err)
		}
	}

	// Run migrations
	if err := db.RunMigrations(database, direction); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	// Get current version
	version, dirty, err := db.GetMigrationVersion(database)
	if err != nil {
		return fmt.Errorf("failed to get migration version: %w", err)
	}

	log.Printf("Migration completed successfully. Current version: %d (dirty: %v)", version, dirty) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input
	return nil
}
