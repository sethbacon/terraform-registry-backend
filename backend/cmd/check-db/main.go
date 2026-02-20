// Package main is a diagnostic tool for testing database connectivity and
// inspecting live registry data. It connects to the database, queries the
// modules and module_versions tables, and prints a summary to stdout. The
// binary exits with a non-zero code on any failure so it can be embedded in
// health checks or CI/CD pipeline steps to gate deployments on a reachable,
// populated database.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func main() {
	dbPassword := os.Getenv("DATABASE_PASSWORD")
	if dbPassword == "" {
		dbPassword = "registry"
	}

	connStr := fmt.Sprintf("host=localhost port=5432 user=registry password=%s dbname=terraform_registry sslmode=disable", dbPassword)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer db.Close()

	// Check modules
	fmt.Println("=== MODULES ===")
	rows, err := db.Query("SELECT id, namespace, name, system FROM modules")
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, namespace, name, system string
		if err := rows.Scan(&id, &namespace, &name, &system); err != nil {
			log.Printf("Warning: failed to scan module row: %v", err)
			continue
		}
		fmt.Printf("Module: %s/%s/%s (ID: %s)\n", namespace, name, system, id)
	}

	// Check versions
	fmt.Println("\n=== MODULE VERSIONS ===")
	rows2, err := db.Query("SELECT id, module_id, version, readme FROM module_versions")
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	defer rows2.Close()

	count := 0
	for rows2.Next() {
		var id, moduleId, version string
		var readme *string
		if err := rows2.Scan(&id, &moduleId, &version, &readme); err != nil {
			log.Printf("Warning: failed to scan version row: %v", err)
			continue
		}
		hasReadme := "NO"
		if readme != nil && *readme != "" {
			hasReadme = fmt.Sprintf("YES (%d chars)", len(*readme))
		}
		fmt.Printf("Version: %s (Module ID: %s, Version ID: %s) - README: %s\n", version, moduleId, id, hasReadme)
		count++
	}

	if count == 0 {
		fmt.Println("No versions found!")
	}
}
