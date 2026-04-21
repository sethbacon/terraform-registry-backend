// Package db — dialect.go defines the Dialect interface that abstracts
// database-specific SQL differences between PostgreSQL and MySQL.
//
// All repository queries should use dialect methods instead of hardcoding
// PostgreSQL-specific syntax (e.g., $1 placeholders, SERIAL, TIMESTAMPTZ).
package db

import "database/sql"

// Dialect abstracts database-specific SQL differences.
type Dialect interface {
	// Name returns the dialect name ("postgres" or "mysql").
	Name() string

	// Placeholder returns the parameter placeholder for the given 1-based index.
	// PostgreSQL: $1, $2, $3
	// MySQL: ?, ?, ?
	Placeholder(index int) string

	// AutoIncrement returns the column type for auto-incrementing primary keys.
	// PostgreSQL: BIGSERIAL
	// MySQL: BIGINT AUTO_INCREMENT
	AutoIncrement() string

	// TimestampType returns the column type for timestamp with timezone.
	// PostgreSQL: TIMESTAMPTZ
	// MySQL: DATETIME(6)
	TimestampType() string

	// Now returns the SQL expression for the current timestamp.
	// PostgreSQL: NOW()
	// MySQL: NOW(6)
	Now() string

	// BoolType returns the column type for booleans.
	// PostgreSQL: BOOLEAN
	// MySQL: TINYINT(1)
	BoolType() string

	// JSONType returns the column type for JSON data.
	// PostgreSQL: JSONB
	// MySQL: JSON
	JSONType() string

	// UpsertSuffix returns the ON CONFLICT/ON DUPLICATE KEY clause for upserts.
	// PostgreSQL: ON CONFLICT (...) DO UPDATE SET ...
	// MySQL: ON DUPLICATE KEY UPDATE ...
	UpsertSuffix(conflictColumns []string, updateColumns []string) string

	// MigrationsPath returns the filesystem path to migration files for this dialect.
	MigrationsPath() string

	// Open opens a database connection for this dialect.
	Open(dsn string) (*sql.DB, error)
}

// PostgresDialect implements Dialect for PostgreSQL.
type PostgresDialect struct{}

// NewPostgresDialect creates a new PostgreSQL dialect.
func NewPostgresDialect() *PostgresDialect {
	return &PostgresDialect{}
}

func (d *PostgresDialect) Name() string { return "postgres" }

func (d *PostgresDialect) Placeholder(index int) string {
	return "$" + itoa(index)
}

func (d *PostgresDialect) AutoIncrement() string { return "BIGSERIAL" }
func (d *PostgresDialect) TimestampType() string { return "TIMESTAMPTZ" }
func (d *PostgresDialect) Now() string           { return "NOW()" }
func (d *PostgresDialect) BoolType() string      { return "BOOLEAN" }
func (d *PostgresDialect) JSONType() string      { return "JSONB" }

func (d *PostgresDialect) UpsertSuffix(conflictCols []string, updateCols []string) string {
	result := "ON CONFLICT ("
	for i, col := range conflictCols {
		if i > 0 {
			result += ", "
		}
		result += col
	}
	result += ") DO UPDATE SET "
	for i, col := range updateCols {
		if i > 0 {
			result += ", "
		}
		result += col + " = EXCLUDED." + col
	}
	return result
}

func (d *PostgresDialect) MigrationsPath() string {
	return "internal/db/migrations"
}

func (d *PostgresDialect) Open(dsn string) (*sql.DB, error) {
	return sql.Open("postgres", dsn)
}

// MysqlDialect implements Dialect for MySQL.
type MysqlDialect struct{}

// NewMysqlDialect creates a new MySQL dialect.
func NewMysqlDialect() *MysqlDialect {
	return &MysqlDialect{}
}

func (d *MysqlDialect) Name() string { return "mysql" }

func (d *MysqlDialect) Placeholder(_ int) string {
	return "?"
}

func (d *MysqlDialect) AutoIncrement() string { return "BIGINT AUTO_INCREMENT" }
func (d *MysqlDialect) TimestampType() string { return "DATETIME(6)" }
func (d *MysqlDialect) Now() string           { return "NOW(6)" }
func (d *MysqlDialect) BoolType() string      { return "TINYINT(1)" }
func (d *MysqlDialect) JSONType() string      { return "JSON" }

func (d *MysqlDialect) UpsertSuffix(_ []string, updateCols []string) string {
	result := "ON DUPLICATE KEY UPDATE "
	for i, col := range updateCols {
		if i > 0 {
			result += ", "
		}
		result += col + " = VALUES(" + col + ")"
	}
	return result
}

func (d *MysqlDialect) MigrationsPath() string {
	return "internal/db/migrations_mysql"
}

func (d *MysqlDialect) Open(dsn string) (*sql.DB, error) {
	return sql.Open("mysql", dsn)
}

// GetDialect returns the appropriate Dialect for the given database type.
func GetDialect(dbType string) Dialect {
	switch dbType {
	case "mysql":
		return NewMysqlDialect()
	default:
		return NewPostgresDialect()
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}
