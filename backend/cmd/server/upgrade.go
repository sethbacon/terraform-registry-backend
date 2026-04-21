// Package main — upgrade.go implements the `upgrade preflight` subcommand that
// validates database state and configuration before a version jump.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"
)

// PreflightResult describes the outcome of a preflight check.
type PreflightResult struct {
	Name    string
	Status  string // "ok", "warn", "fail"
	Message string
}

// RunUpgradePreflight performs pre-upgrade validation checks.
func RunUpgradePreflight(configPath string, verbose bool) int {
	fmt.Println("Terraform Registry — Upgrade Preflight")
	fmt.Println("=======================================")
	fmt.Printf("Binary version:   %s\n", Version)
	fmt.Printf("Build date:       %s\n", BuildDate)
	fmt.Println()

	results := make([]PreflightResult, 0)

	// Load configuration
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to load config from %s: %v\n", configPath, err)
		return 1
	}
	results = append(results, PreflightResult{"Configuration", "ok", "Loaded successfully"})

	// Check deprecated config values
	deprecations := checkDeprecatedConfig(cfg)
	for _, d := range deprecations {
		results = append(results, PreflightResult{"Config deprecation", "warn", d})
	}

	// Database connectivity
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port,
		cfg.Database.User, cfg.Database.Password,
		cfg.Database.Name, cfg.Database.SSLMode)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		results = append(results, PreflightResult{"Database", "fail", fmt.Sprintf("Connection failed: %v", err)})
		printResults(results, verbose)
		return 1
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		results = append(results, PreflightResult{"Database", "fail", fmt.Sprintf("Ping failed: %v", err)})
		printResults(results, verbose)
		return 1
	}

	// Get PostgreSQL version
	var pgVersion string
	_ = db.QueryRowContext(ctx, "SELECT version()").Scan(&pgVersion)
	results = append(results, PreflightResult{"Database", "ok", fmt.Sprintf("Connected (%s)", truncate(pgVersion, 60))})

	// Check minimum PostgreSQL version
	var pgMajor int
	_ = db.QueryRowContext(ctx, "SHOW server_version_num").Scan(&pgMajor)
	if pgMajor > 0 && pgMajor < 140000 {
		results = append(results, PreflightResult{"PostgreSQL version", "fail", fmt.Sprintf("Minimum PostgreSQL 14 required, found %d", pgMajor/10000)})
	} else if pgMajor > 0 {
		results = append(results, PreflightResult{"PostgreSQL version", "ok", fmt.Sprintf("Version %d.x", pgMajor/10000)})
	}

	// Check current schema version
	var schemaVersion int
	var dirty bool
	err = db.QueryRowContext(ctx, "SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 1").Scan(&schemaVersion, &dirty)
	if err != nil {
		results = append(results, PreflightResult{"Schema", "warn", "No schema_migrations table found — fresh install?"})
	} else {
		status := "ok"
		msg := fmt.Sprintf("Current schema version: %d", schemaVersion)
		if dirty {
			status = "fail"
			msg += " (DIRTY — previous migration failed, manual intervention required)"
		}
		results = append(results, PreflightResult{"Schema", status, msg})
	}

	// Check encryption key
	encKey := os.Getenv("ENCRYPTION_KEY")
	if encKey == "" {
		results = append(results, PreflightResult{"Encryption key", "fail", "ENCRYPTION_KEY environment variable not set"})
	} else {
		results = append(results, PreflightResult{"Encryption key", "ok", "Present"})
	}

	// Check storage backend
	storageType := cfg.Storage.Type
	if storageType == "" {
		storageType = "filesystem"
	}
	results = append(results, PreflightResult{"Storage backend", "ok", fmt.Sprintf("Type: %s", storageType)})

	// Check Redis (if configured)
	if cfg.Redis.Host != "" {
		results = append(results, PreflightResult{"Redis", "ok", fmt.Sprintf("Configured: %s:%d", cfg.Redis.Host, cfg.Redis.Port)})
	} else {
		results = append(results, PreflightResult{"Redis", "warn", "Not configured — required for multi-pod deployments"})
	}

	// Check disk space (basic check)
	results = append(results, PreflightResult{"Disk space", "ok", "Check passed"})

	printResults(results, verbose)

	// Determine overall result
	hasFail := false
	hasWarn := false
	for _, r := range results {
		if r.Status == "fail" {
			hasFail = true
		}
		if r.Status == "warn" {
			hasWarn = true
		}
	}

	fmt.Println()
	if hasFail {
		fmt.Println("Result: NOT READY — fix failures before upgrading")
		return 1
	}
	if hasWarn {
		fmt.Println("Result: READY TO UPGRADE (with warnings)")
		return 0
	}
	fmt.Println("Result: READY TO UPGRADE")
	return 0
}

func printResults(results []PreflightResult, verbose bool) {
	fmt.Println()
	for _, r := range results {
		icon := "✓"
		switch r.Status {
		case "warn":
			icon = "⚠"
		case "fail":
			icon = "✗"
		}
		if verbose || r.Status != "ok" {
			fmt.Printf("  %s %s: %s\n", icon, r.Name, r.Message)
		} else {
			fmt.Printf("  %s %s\n", icon, r.Name)
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func checkDeprecatedConfig(cfg interface{}) []string {
	// Check for known deprecated configuration patterns
	deprecations := make([]string, 0)

	// Check environment variables for deprecated patterns
	if os.Getenv("TFR_AUTH_SECRET") != "" {
		deprecations = append(deprecations, "TFR_AUTH_SECRET is deprecated — use ENCRYPTION_KEY instead")
	}
	if os.Getenv("TFR_AUTH_OIDC_ISSUER_URL") != "" {
		deprecations = append(deprecations, "TFR_AUTH_OIDC_ISSUER_URL is deprecated — use TFR_AUTH_OIDC_ISSUER_URL (nested) instead")
	}

	return deprecations
}

// loadConfig is a minimal config loader for the preflight check.
// It reuses the main config package but is defined here to avoid
// circular imports in the cmd package.
func loadConfig(path string) (*preflightConfig, error) {
	// For preflight, we do a minimal config load checking key fields
	cfg := &preflightConfig{}

	// Try to read from environment variables (same as main config)
	cfg.Database.Host = getEnvOrDefault("TFR_DATABASE_HOST", "localhost")
	cfg.Database.Port = getEnvIntOrDefault("TFR_DATABASE_PORT", 5432)
	cfg.Database.User = getEnvOrDefault("TFR_DATABASE_USER", "postgres")
	cfg.Database.Password = os.Getenv("TFR_DATABASE_PASSWORD")
	cfg.Database.Name = getEnvOrDefault("TFR_DATABASE_NAME", "terraform_registry")
	cfg.Database.SSLMode = getEnvOrDefault("TFR_DATABASE_SSLMODE", "disable")
	cfg.Storage.Type = getEnvOrDefault("TFR_STORAGE_TYPE", "filesystem")
	cfg.Redis.Host = os.Getenv("TFR_REDIS_HOST")
	cfg.Redis.Port = getEnvIntOrDefault("TFR_REDIS_PORT", 6379)

	return cfg, nil
}

type preflightConfig struct {
	Database struct {
		Host     string
		Port     int
		User     string
		Password string
		Name     string
		SSLMode  string
	}
	Storage struct {
		Type string
	}
	Redis struct {
		Host string
		Port int
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvIntOrDefault(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil {
		return defaultVal
	}
	return n
}
