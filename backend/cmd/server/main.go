// @title           Terraform Registry API
// @version         1.0.0
// @description     Complete Terraform Module and Provider Registry with SCM integration, mirrors, and storage backends
// @termsOfService  https://registry.terraform.io/terms
// @contact.name    Support
// @contact.email   support@example.com
// @license.name    Apache-2.0
// @basePath        /
// @schemes         http https
// @securityDefinitions.apiKey  Bearer
// @in                          header
// @name                         Authorization
// @description                  "JWT token or API key. For JWT: 'Bearer {token}'. For API Key: 'Bearer {api_key}'"
//
// @tag.name         System
// @tag.description  Health, readiness, and service-discovery endpoints.
//
// @tag.name         Observability
// @tag.description  Prometheus metrics and profiling are served on a dedicated side-channel port (default: 9090) that is separate from the main API server. This keeps the scrape path off the public ingress and avoids rate-limiting middleware. Configure the port with TFR_TELEMETRY_METRICS_PROMETHEUS_PORT. The endpoint path is always GET /metrics. pprof (if enabled via TFR_TELEMETRY_PROFILING_ENABLED=true) is served on TFR_TELEMETRY_PROFILING_PORT (default: 6060) at the standard /debug/pprof/ paths. Neither endpoint is part of the OpenAPI spec because they are not served by the Gin router.

// Package main is the entry point for the Terraform Registry server binary.
// It dispatches three subcommands — serve, migrate, and version — via a simple
// switch on os.Args so the binary's full CLI surface is readable in one place
// without requiring a cobra dependency. The serve command runs auto-migration on
// startup so freshly deployed containers never need a separate migration step.
package main

import (
	"context"
	"crypto/rand"
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
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/terraform-registry/terraform-registry/internal/api"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/telemetry"
	"golang.org/x/crypto/bcrypt"
)

const (
	version = "0.1.0"
)

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
		return serve(cfg)
	case "migrate":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: %s migrate <up|down>", os.Args[0])
		}
		return runMigrations(cfg, os.Args[2])
	case "version":
		fmt.Printf("Terraform Registry v%s\n", version)
		return nil
	default:
		return fmt.Errorf("unknown command: %s\nAvailable commands: serve, migrate, version", command)
	}
}

func serve(cfg *config.Config) error {
	// Initialise structured logger as early as possible so all subsequent log output
	// uses the configured format (json / text) and level.
	telemetry.SetupLogger(cfg.Logging.Format, cfg.Logging.Level)

	// Set Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Validate JWT secret configuration (fails in production if not set)
	if err := auth.ValidateJWTSecret(); err != nil {
		return fmt.Errorf("security configuration error: %w", err)
	}
	log.Println("JWT secret validated successfully")

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

	// Create router
	router, bgServices := api.NewRouter(cfg, database)

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.Server.GetAddress(),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on %s", cfg.Server.GetAddress())
		log.Printf("Base URL: %s", cfg.Server.BaseURL)
		log.Printf("Storage backend: %s", cfg.Storage.DefaultBackend)
		log.Printf("Multi-tenancy: %v", cfg.MultiTenancy.Enabled)
		log.Println("Server is ready to accept connections")

		var err error
		if cfg.Security.TLS.Enabled {
			log.Printf("TLS enabled: cert=%s, key=%s", cfg.Security.TLS.CertFile, cfg.Security.TLS.KeyFile)
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
		return nil // Setup already done, nothing to do
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

	// Bcrypt-hash the token (cost 12) before storing
	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), 12)
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

func runMigrations(cfg *config.Config, direction string) error {
	// Connect to database
	database, err := db.Connect(cfg.Database.GetDSN(), cfg.Database.MaxConnections, cfg.Database.MinIdleConnections)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	log.Printf("Running migrations: %s", direction) // #nosec G706 -- logged value is application-internal (config string, integer, or application-constructed path); not raw user-controlled request input

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
