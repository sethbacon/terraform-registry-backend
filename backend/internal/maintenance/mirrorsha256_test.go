package maintenance

import (
	"context"
	"errors"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// Issue #869. What an operator relies on from this command: it names every
// affected binary, it distinguishes "there is a SUMS blob we failed to read a
// column out of" from "this version predates checksum persistence", and it
// exits non-zero while any remain so a runbook or CI step can gate on it.

func TestVerifyMirrorSHA256_ReportsEveryAffectedBinary(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`FROM terraform_version_platforms p`).
		WillReturnRows(mock.NewRows([]string{"name", "tool", "version", "os", "arch", "filename", "has_sums"}).
			// The reported case: SUMS blob present, column empty.
			AddRow("tools", "terraform-docs", "0.24.0", "linux", "amd64", "terraform-docs-v0.24.0-linux-amd64.tar.gz", true).
			AddRow("tools", "terraform-docs", "0.23.0", "linux", "amd64", "terraform-docs-v0.23.0-linux-amd64.tar.gz", true).
			// The legacy shape: no SUMS blob either.
			AddRow("hashicorp", "terraform", "1.13.4", "linux", "amd64", "terraform_1.13.4_linux_amd64.zip", false))

	found, verifyErr := VerifyMirrorSHA256(context.Background(), db)

	if !errors.Is(verifyErr, ErrUnverifiableBinariesRemain) {
		t.Fatalf("err = %v, want ErrUnverifiableBinariesRemain — the command must exit non-zero while any remain", verifyErr)
	}
	if len(found) != 3 {
		t.Fatalf("found %d rows, want 3", len(found))
	}
	if found[0].Version != "0.24.0" || found[0].Filename != "terraform-docs-v0.24.0-linux-amd64.tar.gz" {
		t.Errorf("found[0] = %+v, want the terraform-docs 0.24.0 linux/amd64 row", found[0])
	}
	if !found[0].HasSums {
		t.Error("found[0].HasSums = false, want true — this version has a stored SUMS blob")
	}
	if found[2].HasSums {
		t.Error("found[2].HasSums = true, want false — the legacy row has no SUMS blob")
	}

	line := found[0].String()
	for _, want := range []string{"tools", "terraform-docs", "0.24.0", "linux/amd64", "sums-blob-stored"} {
		if !strings.Contains(line, want) {
			t.Errorf("String() = %q, want it to contain %q", line, want)
		}
	}
	if !strings.Contains(found[2].String(), "no-sums-blob") {
		t.Errorf("String() = %q, want no-sums-blob for a version with no stored SUMS", found[2].String())
	}
}

func TestVerifyMirrorSHA256_CleanMirrorReturnsNoError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`FROM terraform_version_platforms p`).
		WillReturnRows(mock.NewRows([]string{"name", "tool", "version", "os", "arch", "filename", "has_sums"}))

	found, verifyErr := VerifyMirrorSHA256(context.Background(), db)
	if verifyErr != nil {
		t.Fatalf("err = %v, want nil for a clean mirror", verifyErr)
	}
	if len(found) != 0 {
		t.Errorf("found %d rows, want 0", len(found))
	}
}

// A query failure must not be reported as a clean mirror: that would turn the
// gate green on a database it never managed to ask.
func TestVerifyMirrorSHA256_QueryErrorIsNotCleanliness(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`FROM terraform_version_platforms p`).
		WillReturnError(errors.New("connection refused"))

	found, verifyErr := VerifyMirrorSHA256(context.Background(), db)
	if verifyErr == nil {
		t.Fatal("expected an error when the query fails, got nil")
	}
	if errors.Is(verifyErr, ErrUnverifiableBinariesRemain) {
		t.Error("a query failure must not be reported as findings")
	}
	if !strings.Contains(verifyErr.Error(), "failed to query mirrored platforms") {
		t.Errorf("err = %v, want the query failure named", verifyErr)
	}
	if found != nil {
		t.Errorf("found = %+v, want nil", found)
	}
}

func TestVerifyMirrorSHA256_NilDatabase(t *testing.T) {
	found, err := VerifyMirrorSHA256(context.Background(), nil)
	if err == nil {
		t.Fatal("expected an error for a nil database handle, got nil")
	}
	if found != nil {
		t.Errorf("found = %+v, want nil", found)
	}
}

// The query is only useful if it cannot silently narrow. These are the three
// clauses that decide what the audit covers.
func TestVerifyMirrorSHA256_QueryScope(t *testing.T) {
	for _, want := range []string{
		"p.sync_status = 'synced'", // only rows the registry actually serves
		"p.sha256 = ''",            // the defect state itself
		"v.is_deprecated = false",  // a retired version must not hold the gate red
	} {
		if !strings.Contains(verifyMirrorSHA256Query, want) {
			t.Errorf("audit query is missing %q — it no longer asks the question the command claims to answer", want)
		}
	}
	// Reading the answer out of our own storage would collapse the two
	// authorities the inline sha256 exists to keep apart.
	if strings.Contains(verifyMirrorSHA256Query, "UPDATE") || strings.Contains(verifyMirrorSHA256Query, "INSERT") {
		t.Error("the audit query must be read-only")
	}
}

func TestSummariseUnverifiable_GroupsByConfigAndTool(t *testing.T) {
	found := []UnverifiablePlatform{
		{Config: "tools", Tool: "terraform-docs", Version: "0.24.0"},
		{Config: "tools", Tool: "terraform-docs", Version: "0.23.0"},
		{Config: "hashicorp", Tool: "terraform", Version: "1.13.4"},
	}
	got := SummariseUnverifiable(found)
	if len(got) != 2 {
		t.Fatalf("got %d summary lines, want 2: %v", len(got), got)
	}
	// Sorted, so hashicorp precedes tools.
	if !strings.Contains(got[0], "hashicorp (terraform): 1 platform(s)") {
		t.Errorf("got[0] = %q", got[0])
	}
	if !strings.Contains(got[1], "tools (terraform-docs): 2 platform(s)") {
		t.Errorf("got[1] = %q", got[1])
	}
}

func TestFormatUnverifiable_OneRowPerLine(t *testing.T) {
	out := FormatUnverifiable([]UnverifiablePlatform{
		{Config: "tools", Tool: "terraform-docs", Version: "0.24.0", OS: "linux", Arch: "amd64", Filename: "a.tar.gz", HasSums: true},
		{Config: "tools", Tool: "terraform-docs", Version: "0.23.0", OS: "linux", Arch: "amd64", Filename: "b.tar.gz", HasSums: true},
	})
	if lines := strings.Count(out, "\n"); lines != 2 {
		t.Errorf("got %d lines, want 2:\n%s", lines, out)
	}
	if !strings.Contains(out, "a.tar.gz") || !strings.Contains(out, "b.tar.gz") {
		t.Errorf("output does not name both binaries:\n%s", out)
	}
}
