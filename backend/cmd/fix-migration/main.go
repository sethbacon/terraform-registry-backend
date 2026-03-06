// Package main is a repair tool for dirty migration state in the registry
// database. Dirty state occurs when the golang-migrate runner marks a migration
// version as dirty (dirty=true) but the process was interrupted before it could
// complete. This tool connects to the database, reports the current migration
// state, and — unless --dry-run is set — clears the dirty flag so that the
// server can retry the migration cleanly on next startup.
//
// Environment variables (mirrors the TFR_ prefix used by cmd/server):
//
//	TFR_DATABASE_HOST      — default: localhost
//	TFR_DATABASE_PORT      — default: 5432
//	TFR_DATABASE_USER      — default: registry
//	TFR_DATABASE_PASSWORD  — default: registry
//	TFR_DATABASE_NAME      — default: terraform_registry
//	TFR_DATABASE_SSL_MODE  — default: disable
//
// Flags:
//
//	--dry-run   Report migration state without making any changes
package main

import (
	"database/sql"
	"flag"
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
	dryRun := flag.Bool("dry-run", false, "Report migration state without making changes")
	flag.Parse()

	host := env("TFR_DATABASE_HOST", "localhost")
	port := env("TFR_DATABASE_PORT", "5432")
	user := env("TFR_DATABASE_USER", "registry")
	password := env("TFR_DATABASE_PASSWORD", "registry")
	dbname := env("TFR_DATABASE_NAME", "terraform_registry")
	sslmode := env("TFR_DATABASE_SSL_MODE", "disable")

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to open connection: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to connect to %s:%s/%s: %v", host, port, dbname, err)
	}
	log.Printf("Connected to %s:%s/%s as %s", host, port, dbname, user)

	var version int
	var dirty bool
	err = db.QueryRow("SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if err != nil {
		log.Fatalf("Failed to read schema_migrations: %v", err)
	}
	log.Printf("Current migration state: version=%d, dirty=%v", version, dirty)

	if !dirty {
		log.Println("Migration state is clean — no action required.")
		return
	}

	if *dryRun {
		log.Printf("--dry-run set: would clear dirty flag on version %d (no changes made)", version)
		os.Exit(0)
	}

	log.Printf("Clearing dirty flag on version %d ...", version)
	_, err = db.Exec("UPDATE schema_migrations SET dirty = false")
	if err != nil {
		log.Fatalf("Failed to clear dirty flag: %v", err)
	}

	// Confirm
	err = db.QueryRow("SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if err != nil {
		log.Fatalf("Failed to re-read schema_migrations after update: %v", err)
	}
	log.Printf("Done. Migration state: version=%d, dirty=%v", version, dirty)
}
