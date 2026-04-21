package db

import "testing"

func TestPostgresDialect(t *testing.T) {
	d := NewPostgresDialect()
	if d.Name() != "postgres" {
		t.Errorf("Name() = %q, want postgres", d.Name())
	}
	if got := d.Placeholder(1); got != "$1" {
		t.Errorf("Placeholder(1) = %q, want $1", got)
	}
	if got := d.Placeholder(12); got != "$12" {
		t.Errorf("Placeholder(12) = %q, want $12", got)
	}
	if got := d.AutoIncrement(); got != "BIGSERIAL" {
		t.Errorf("AutoIncrement() = %q", got)
	}
	if got := d.TimestampType(); got != "TIMESTAMPTZ" {
		t.Errorf("TimestampType() = %q", got)
	}
	if got := d.Now(); got != "NOW()" {
		t.Errorf("Now() = %q", got)
	}
	if got := d.BoolType(); got != "BOOLEAN" {
		t.Errorf("BoolType() = %q", got)
	}
	if got := d.JSONType(); got != "JSONB" {
		t.Errorf("JSONType() = %q", got)
	}
	if got := d.MigrationsPath(); got != "internal/db/migrations" {
		t.Errorf("MigrationsPath() = %q", got)
	}

	upsert := d.UpsertSuffix([]string{"id"}, []string{"name", "value"})
	expected := "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, value = EXCLUDED.value"
	if upsert != expected {
		t.Errorf("UpsertSuffix() = %q, want %q", upsert, expected)
	}
}

func TestMysqlDialect(t *testing.T) {
	d := NewMysqlDialect()
	if d.Name() != "mysql" {
		t.Errorf("Name() = %q, want mysql", d.Name())
	}
	if got := d.Placeholder(1); got != "?" {
		t.Errorf("Placeholder(1) = %q, want ?", got)
	}
	if got := d.AutoIncrement(); got != "BIGINT AUTO_INCREMENT" {
		t.Errorf("AutoIncrement() = %q", got)
	}
	if got := d.TimestampType(); got != "DATETIME(6)" {
		t.Errorf("TimestampType() = %q", got)
	}
	if got := d.Now(); got != "NOW(6)" {
		t.Errorf("Now() = %q", got)
	}
	if got := d.BoolType(); got != "TINYINT(1)" {
		t.Errorf("BoolType() = %q", got)
	}
	if got := d.JSONType(); got != "JSON" {
		t.Errorf("JSONType() = %q", got)
	}
	if got := d.MigrationsPath(); got != "internal/db/migrations_mysql" {
		t.Errorf("MigrationsPath() = %q", got)
	}

	upsert := d.UpsertSuffix([]string{"id"}, []string{"name", "value"})
	expected := "ON DUPLICATE KEY UPDATE name = VALUES(name), value = VALUES(value)"
	if upsert != expected {
		t.Errorf("UpsertSuffix() = %q, want %q", upsert, expected)
	}
}

func TestGetDialect(t *testing.T) {
	pg := GetDialect("postgres")
	if pg.Name() != "postgres" {
		t.Errorf("GetDialect(postgres) returned %q", pg.Name())
	}
	my := GetDialect("mysql")
	if my.Name() != "mysql" {
		t.Errorf("GetDialect(mysql) returned %q", my.Name())
	}
	def := GetDialect("unknown")
	if def.Name() != "postgres" {
		t.Errorf("GetDialect(unknown) should default to postgres, got %q", def.Name())
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{99, "99"},
		{123, "123"},
	}
	for _, tt := range tests {
		// Test via Placeholder which uses itoa
		d := NewPostgresDialect()
		got := d.Placeholder(tt.in)
		if got != "$"+tt.want {
			t.Errorf("Placeholder(%d) = %q, want $%s", tt.in, got, tt.want)
		}
	}
}
