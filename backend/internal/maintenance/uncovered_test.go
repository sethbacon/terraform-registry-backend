package maintenance

// uncovered_test.go holds the registry of uncovered columns to the same standard
// as the coverage guard next to it: checked in BOTH directions, because a
// one-way check rots.
//
// The two lists describe the same set from opposite ends -- the guard says
// "these AAD derivations are deliberately not swept", this registry says "these
// columns therefore need counting so the operator hears about them". If they can
// drift, the failure is silent and lands in exactly the place #878 is about: an
// exemption gets added, the operator is told nothing about the rows behind it,
// and verify keeps exiting zero over a set narrower than they believe.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestUncoveredRegistryMatchesCoverageExemptions(t *testing.T) {
	declared := map[string]int{}
	for _, f := range UncoveredContextFuncs() {
		declared[f]++
	}

	// Every exemption must produce a report. This is the direction that
	// matters most: an exemption without one is a column the gate excludes
	// and never mentions, which is the defect itself.
	for fn := range unsweptAADContexts {
		if declared[fn] == 0 {
			t.Errorf("AAD context %q is exempted from the rekey sweep but no uncovered column reports it.\n"+
				"An operator running `rekey-secrets verify` would be told nothing about those rows and could "+
				"drop ENCRYPTION_KEY_PREVIOUS believing they were covered.\n"+
				"Add an entry to uncoveredColumns in uncovered.go naming the column and a COUNT for it.", fn)
		}
	}

	// And no report may name an exemption that no longer exists -- that is a
	// column being counted and warned about after it started being swept,
	// which teaches operators to ignore the warning.
	for fn := range declared {
		if _, ok := unsweptAADContexts[fn]; !ok {
			t.Errorf("uncoveredColumns reports AAD context %q, but it is not exempted in unsweptAADContexts.\n"+
				"Either it is swept now (drop the uncovered entry) or the guard has lost the exemption.", fn)
		}
	}
}

func TestUncoveredRegistryIsWellFormed(t *testing.T) {
	if len(uncoveredColumns) == 0 {
		t.Fatal("uncoveredColumns is empty; the bidirectional check above would then pass vacuously")
	}
	seen := map[string]bool{}
	for _, c := range uncoveredColumns {
		switch {
		case c.Name == "":
			t.Error("an uncovered column has no name; the operator warning would not say which column")
		case c.ContextFunc == "":
			t.Errorf("uncovered column %q has no ContextFunc, so it cannot be joined to the coverage guard", c.Name)
		case c.Reason == "":
			t.Errorf("uncovered column %q has no reason; a warning without one reads as noise and gets ignored", c.Name)
		case !strings.Contains(c.Name, "."):
			t.Errorf("uncovered column %q is not in table.column form, so its COUNT cannot be built from it", c.Name)
		}
		if seen[c.Name] {
			t.Errorf("uncovered column %q is listed twice; it would be counted and warned about twice", c.Name)
		}
		seen[c.Name] = true
	}
}

// TestReportUncoveredCountsOnlyNonEmptyAndNeverWrites is the safety property.
//
// This whole feature exists BECAUSE re-encrypting these columns is unsafe to do
// blind: the AAD derives from the row's user and provider ids, and TokenCipher's
// legacy fallback discards a supplied AAD -- so a wrong derivation opens an
// unbound row anyway, re-seals it wrongly, and passes its own round-trip proof.
// The count is the safe half. sqlmock fails the test on any statement that was
// not expected, so an UPDATE or a ciphertext read introduced here is caught.
func TestReportUncoveredCountsOnlyNonEmptyAndNeverWrites(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	for i := range uncoveredColumns {
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)`)).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(i + 1))
	}

	got := ReportUncovered(context.Background(), db)
	if len(got) != len(uncoveredColumns) {
		t.Fatalf("reported %d columns, registry has %d", len(got), len(uncoveredColumns))
	}
	for i, r := range got {
		if r.CountFailed != nil {
			t.Errorf("%s: unexpected count failure: %v", r.Column, r.CountFailed)
		}
		if r.Rows != i+1 {
			t.Errorf("%s: rows = %d, want %d", r.Column, r.Rows, i+1)
		}
		if r.Reason == "" {
			t.Errorf("%s: reason did not survive into the report", r.Column)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestReportUncoveredKeepsGoingWhenOneCountFails guards the reason the report
// does not abort on error.
//
// Losing every column's message because one table was unreadable would reinstate
// precisely the silence this exists to end -- and it would do it on the runs
// most likely to be unusual, which are the runs where the operator most needs
// the list.
func TestReportUncoveredKeepsGoingWhenOneCountFails(t *testing.T) {
	if len(uncoveredColumns) < 2 {
		t.Skip("needs at least two columns to show the second still reports")
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	boom := errors.New("relation does not exist")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)`)).WillReturnError(boom)
	for range uncoveredColumns[1:] {
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)`)).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))
	}

	got := ReportUncovered(context.Background(), db)
	if len(got) != len(uncoveredColumns) {
		t.Fatalf("a failing count truncated the report: got %d of %d columns", len(got), len(uncoveredColumns))
	}
	if !errors.Is(got[0].CountFailed, boom) {
		t.Errorf("first column: CountFailed = %v, want the query error surfaced", got[0].CountFailed)
	}
	if got[0].Rows != 0 {
		t.Errorf("a failed count reported %d rows; it must not look like a real zero", got[0].Rows)
	}
	for _, r := range got[1:] {
		if r.CountFailed != nil {
			t.Errorf("%s: reporting stopped after the failure: %v", r.Column, r.CountFailed)
		}
		if r.Rows != 7 {
			t.Errorf("%s: rows = %d, want 7", r.Column, r.Rows)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestUncoveredCountsTargetRealColumns keeps the COUNT statements honest.
//
// A count against a misspelled column errors at runtime and shows up as
// "population unknown" -- which is a softer, more ignorable version of the
// silence this replaces. The names are checked against the migrations rather
// than trusted.
//
// This assertion is only worth anything because Name IS the query: when the
// registry carried the identifiers a second time inside the count, misspelling
// them there left this test green. Do not reintroduce a second copy.
func TestUncoveredCountsTargetRealColumns(t *testing.T) {
	sorted := make([]string, 0, len(uncoveredColumns))
	for _, c := range uncoveredColumns {
		sorted = append(sorted, c.Name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		if !migrationsDefineColumn(t, name) {
			t.Errorf("uncovered column %q is not defined by any migration; its COUNT would error "+
				"and report the population as unknown", name)
		}
	}
}

// migrationsDefineColumn reports whether "table.column" appears as a column of
// that table anywhere in the migration set.
//
// Deliberately textual and loose: it must tolerate a column arriving in one
// migration and its table in another, so it looks for the table being named and
// the column being named in the same file. It is a typo catcher, not a schema
// model -- the assertion it supports is only "this identifier exists".
//
// MATCHED ON WORD BOUNDARIES, not substrings. A plain strings.Contains was inert
// against the likeliest typo of all -- a dropped trailing letter -- because
// "scm_oauth_token" is a substring of "scm_oauth_tokens" and matched happily.
func identifierRe(name string) *regexp.Regexp {
	// \b is not enough on its own: SQL identifiers contain underscores, which
	// are word characters, so \bscm_oauth_token\b happily matches inside
	// scm_oauth_tokens. Assert the neighbours are not identifier characters.
	return regexp.MustCompile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(name) + `($|[^A-Za-z0-9_])`)
}

func migrationsDefineColumn(t *testing.T, qualified string) bool {
	t.Helper()
	table, column, ok := strings.Cut(qualified, ".")
	if !ok {
		t.Fatalf("uncovered column %q is not in table.column form", qualified)
	}
	dir := filepath.Join("..", "db", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- test-only, directory listing
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		sql := string(b)
		if identifierRe(table).MatchString(sql) && identifierRe(column).MatchString(sql) {
			return true
		}
	}
	return false
}

// TestUncoveredCountRejectsMalformedName covers the branch the registry guard
// makes unreachable, so that if someone relaxes that guard the failure is an
// error rather than a SQL statement built from a half-parsed identifier.
func TestUncoveredCountRejectsMalformedName(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, err = UncoveredColumn{Name: "no_dot_here"}.count(context.Background(), db)
	if err == nil {
		t.Fatal("a name with no table.column split produced no error; a malformed identifier must not reach a statement")
	}
	if !strings.Contains(err.Error(), "table.column") {
		t.Errorf("error does not say what is wrong with the name: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a query was issued for a malformed name: %v", err)
	}
}
