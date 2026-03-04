// Package main is a repair tool for dirty migration state in the registry
// database. Dirty state occurs when the golang-migrate runner marks a migration
// version as in-progress (dirty=true) but the migration process was interrupted
// by a crash or timeout before it could complete. This tool connects to the
// database, checks the schema_migrations table, and clears the dirty flag so
// that the migration runner can retry cleanly on the next server startup — avoiding
// the "Dirty database version" error that would otherwise block the registry from starting.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func main() {
	// Get database password from environment
	password := os.Getenv("DATABASE_PASSWORD")
	if password == "" {
		password = "postgres"
	}

	// Connect to database
	dsn := fmt.Sprintf("host=localhost port=5432 user=registry password=%s dbname=terraform_registry sslmode=disable", password)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Connected to database successfully")

	// Check current migration state
	var version int
	var dirty bool
	err = db.QueryRow("SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if err != nil {
		log.Fatalf("Failed to check migration state: %v", err)
	}

	log.Printf("Current migration state: version=%d, dirty=%v", version, dirty)

	if dirty {
		log.Println("Fixing dirty migration state...")
		_, err = db.Exec("UPDATE schema_migrations SET dirty = false")
		if err != nil {
			log.Fatalf("Failed to fix dirty state: %v", err)
		}
		log.Println("Migration state fixed successfully")
	} else {
		log.Println("Migration state is already clean")
	}

	// Show final state
	err = db.QueryRow("SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if err != nil {
		log.Fatalf("Failed to check final migration state: %v", err)
	}

	log.Printf("Final migration state: version=%d, dirty=%v", version, dirty)
}
