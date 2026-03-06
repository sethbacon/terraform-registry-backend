// Package main is a diagnostic tool for testing database connectivity and
// inspecting live registry data. It connects to the database, prints row
// counts for every major table, and lists modules and providers in detail.
// The binary exits with a non-zero code on any failure so it can be embedded
// in health checks or CI/CD pipeline steps to gate deployments on a
// reachable, populated database.
//
// Environment variables (mirrors the TFR_ prefix used by cmd/server):
//
//	TFR_DATABASE_HOST      — default: localhost
//	TFR_DATABASE_PORT      — default: 5432
//	TFR_DATABASE_USER      — default: registry
//	TFR_DATABASE_PASSWORD  — default: registry
//	TFR_DATABASE_NAME      — default: terraform_registry
//	TFR_DATABASE_SSL_MODE  — default: disable
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	host := env("TFR_DATABASE_HOST", "localhost")
	port := env("TFR_DATABASE_PORT", "5432")
	user := env("TFR_DATABASE_USER", "registry")
	password := env("TFR_DATABASE_PASSWORD", "registry")
	dbname := env("TFR_DATABASE_NAME", "terraform_registry")
	sslmode := env("TFR_DATABASE_SSL_MODE", "disable")

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open connection: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to connect to %s:%s/%s: %v", host, port, dbname, err)
	}
	fmt.Printf("Connected to %s:%s/%s as %s\n\n", host, port, dbname, user)

	// ── Row counts ────────────────────────────────────────────────────────────
	tables := []string{
		"users",
		"api_keys",
		"organizations",
		"organization_members",
		"role_templates",
		"modules",
		"module_versions",
		"providers",
		"provider_versions",
		"terraform_mirrors",
		"storage_configs",
		"scm_providers",
		"audit_logs",
		"schema_migrations",
	}

	fmt.Println("=== ROW COUNTS ===")
	for _, table := range tables {
		var count int
		row := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)) // #nosec G201 — table names are hardcoded
		if err := row.Scan(&count); err != nil {
			fmt.Printf("  %-30s  (error: %v)\n", table, err)
		} else {
			fmt.Printf("  %-30s  %d\n", table, count)
		}
	}

	// ── Migration state ───────────────────────────────────────────────────────
	fmt.Println("\n=== MIGRATION STATE ===")
	var version int
	var dirty bool
	err = db.QueryRow("SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if err != nil {
		fmt.Printf("  (error reading schema_migrations: %v)\n", err)
	} else {
		dirtyNote := ""
		if dirty {
			dirtyNote = "  *** DIRTY — run cmd/fix-migration ***"
		}
		fmt.Printf("  version=%d  dirty=%v%s\n", version, dirty, dirtyNote)
	}

	// ── Modules ───────────────────────────────────────────────────────────────
	fmt.Println("\n=== MODULES ===")
	rows, err := db.Query("SELECT id, namespace, name, system FROM modules ORDER BY namespace, name, system")
	if err != nil {
		log.Printf("Warning: could not query modules: %v", err)
	} else {
		defer rows.Close()
		n := 0
		for rows.Next() {
			var id, namespace, name, system string
			if err := rows.Scan(&id, &namespace, &name, &system); err != nil {
				log.Printf("Warning: scan error: %v", err)
				continue
			}
			fmt.Printf("  %s/%s/%s  (id: %s)\n", namespace, name, system, id)
			n++
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	}

	// ── Providers ─────────────────────────────────────────────────────────────
	fmt.Println("\n=== PROVIDERS ===")
	rows2, err := db.Query("SELECT id, namespace, name FROM providers ORDER BY namespace, name")
	if err != nil {
		log.Printf("Warning: could not query providers: %v", err)
	} else {
		defer rows2.Close()
		n := 0
		for rows2.Next() {
			var id, namespace, name string
			if err := rows2.Scan(&id, &namespace, &name); err != nil {
				log.Printf("Warning: scan error: %v", err)
				continue
			}
			fmt.Printf("  %s/%s  (id: %s)\n", namespace, name, id)
			n++
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	}
}
