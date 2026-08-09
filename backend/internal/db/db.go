// Package db manages database connections and schema migrations for the registry.
// It wraps sqlx for connection pooling and golang-migrate for schema versioning.
// Migrations are embedded in the binary (via go:embed in the migrations package) so the server can apply schema changes on startup without external tooling.
package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Connect establishes a connection to the PostgreSQL database
func Connect(dsn string, maxConnections, minIdleConnections int) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(maxConnections)
	db.SetMaxIdleConns(minIdleConnections)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(30 * time.Second)

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// newMigrator builds a migrator over a single connection borrowed from db.
//
// Every migrator returned here MUST be handed to closeMigrator, which returns
// the borrowed connection to db's pool. Callers keep ownership of db itself,
// which this package never closes.
//
// The borrowing is explicit for a reason (issue #788). postgres.WithInstance(db, ...)
// also checks out a dedicated connection and holds it for the driver's
// lifetime, but it additionally records db on the driver, so the driver's
// Close() closes the caller's shared *sql.DB. That makes the obvious fix --
// "just defer m.Close()" -- worse than the leak it repairs: at startup it would
// close the application pool. postgres.WithConnection takes a connection this
// package obtained itself and leaves the driver's db field nil, so Close()
// releases exactly what was borrowed and nothing more.
//
// Without that release, each call permanently consumed one slot of the pool's
// MaxOpenConns. cmd/server/main.go calls GetMigrationVersion with the
// long-lived application pool, so the loss was not reclaimed until shutdown --
// and that is the pool backing identity queries on the auth hot path.
//
// This mirrors terraform-suite-identity's newMigrator/closeMigrator
// (sethbacon/terraform-suite-identity#139). The same defect was implemented
// twice, so the module-side fix never reached this copy.
func newMigrator(ctx context.Context, db *sql.DB) (*migrate.Migrate, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire a connection for migrations: %w", err)
	}

	driver, err := postgres.WithConnection(ctx, conn, &postgres.Config{})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to create migration driver: %w", err)
	}

	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		// driver.Close() releases the borrowed connection back to db's pool
		// (and only that: WithConnection leaves the driver's db field nil).
		_ = driver.Close()
		return nil, fmt.Errorf("failed to create migration source: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", driver)
	if err != nil {
		_ = driver.Close()
		_ = sourceDriver.Close()
		return nil, fmt.Errorf("failed to create migration instance: %w", err)
	}

	return m, nil
}

// closeMigrator releases the migrator's source driver and returns its borrowed
// connection to the pool it came from. Best-effort by design: a close failure
// must not mask (or manufacture) an error from the migration itself, and the
// connection is released either way.
func closeMigrator(m *migrate.Migrate) {
	if m == nil {
		return
	}
	_, _ = m.Close()
}

// RunMigrations runs database migrations
func RunMigrations(db *sql.DB, direction string) error {
	m, err := newMigrator(context.Background(), db)
	if err != nil {
		return err
	}
	defer closeMigrator(m)

	switch direction {
	case "up":
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			return fmt.Errorf("failed to run migrations: %w", err)
		}
	case "down":
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			return fmt.Errorf("failed to rollback migrations: %w", err)
		}
	default:
		return fmt.Errorf("invalid migration direction: %s (must be 'up' or 'down')", direction)
	}

	return nil
}

// GetMigrationVersion returns the current migration version
func GetMigrationVersion(db *sql.DB) (version uint, dirty bool, err error) {
	m, err := newMigrator(context.Background(), db)
	if err != nil {
		return 0, false, err
	}
	defer closeMigrator(m)

	version, dirty, err = m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return 0, false, fmt.Errorf("failed to get migration version: %w", err)
	}

	return version, dirty, nil
}
