package db

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	idstore "github.com/sethbacon/terraform-suite-identity/identity/store"
)

// Migration 000057 creates legal_holds; terraform-suite-identity's sweep reads
// it. Two repositories, one shape — which is exactly the arrangement that
// drifts (issue #872, and #864's class before it).
//
// The library RENDERS the shape it reads, so the migration does not have to be
// trusted to transcribe it. This test compares the two, and fails when the
// library changes without the migration being regenerated. It is not a style
// check: a column the sweep reads and the table does not have is a sweep that
// errors, and a column the table has and the sweep does not read is a hold
// condition nobody honours.
func TestMigration000057MatchesTheLibraryDDL(t *testing.T) {
	rendered, err := idstore.LegalHoldTableDDL("legal_holds")
	if err != nil {
		t.Fatalf("LegalHoldTableDDL: %v", err)
	}

	path := filepath.Join("migrations", "000057_legal_holds.up.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	got := normaliseSQL(stripSQLComments(string(raw)))
	want := normaliseSQL(rendered)

	if got != want {
		t.Errorf("migration 000057 no longer matches store.LegalHoldTableDDL.\n"+
			"The library renders the shape its sweep predicate reads, so this is a real\n"+
			"divergence rather than a formatting nit — regenerate the migration from it.\n\n"+
			"migration: %s\n\nlibrary:   %s", got, want)
	}
}

// The columns the exemption reads by name must be present. This is deliberately
// redundant with the comparison above: if someone relaxes that test, this one
// still fails on the columns that actually matter.
func TestMigration000057CarriesTheColumnsTheSweepReads(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("migrations", "000057_legal_holds.up.sql"))
	if err != nil {
		t.Fatalf("reading the migration: %v", err)
	}
	body := stripSQLComments(string(raw))

	for _, col := range []string{
		idstore.LegalHoldActiveColumn,
		idstore.LegalHoldStartDateColumn,
		idstore.LegalHoldEndDateColumn,
	} {
		if !regexp.MustCompile(`(?m)^\s*` + col + `\s`).MatchString(body) {
			t.Errorf("migration 000057 has no %q column, but the sweep's NOT EXISTS reads it — "+
				"a sweep against this table would error rather than exempt anything", col)
		}
	}
}

// A down migration that leaves the table behind is worse than one that drops
// it: a sweep on the rolled-back version would keep reading holds nothing
// maintains.
func TestMigration000057DownDropsTheTable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("migrations", "000057_legal_holds.down.sql"))
	if err != nil {
		t.Fatalf("reading the down migration: %v", err)
	}
	if !strings.Contains(stripSQLComments(string(raw)), "DROP TABLE") {
		t.Error("000057's down migration does not drop legal_holds")
	}
}

// stripSQLComments removes -- line comments so prose in the migration header
// does not count as schema.
func stripSQLComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// normaliseSQL collapses whitespace so indentation and trailing newlines do not
// make an identical shape look different.
func normaliseSQL(s string) string {
	return strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(s, " "))
}
