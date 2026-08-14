package repositories

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/sethbacon/terraform-suite-identity/identity/auditoutbox"
)

// Issue #766 — the re-runnable signature for "a privileged mutation with no
// audit record", now run with the shared library's scanner
// (identity/auditoutbox.Guard) rather than this package's own copy.
//
// WHY THE LIBRARY'S. This package's version matched SQL only in string literals
// written INSIDE a function body. This repository's own outbox INSERT was a
// package-level const — so the same idiom applied to a carrier mutation walked
// straight past the guard that existed to catch it. The library's scan resolves
// package-level constants and variables, and literal concatenation, before
// matching. It is strictly stronger, and TestCarrierMutationGuardIsLive proves
// it on exactly that idiom.
//
// WHAT IT PROTECTS NOW. The carrier's own Grant and Revoke live in
// platformadmin.Carrier and are guarded there. What is guarded HERE is the way
// back in: a hand-written mutation of platform_admins added to this package,
// which would bypass the mechanism, its mandatory AuditIntentWriter and
// migration 000052's constraint trigger check at the Go layer. Module-wide
// coverage of raw carrier SQL is separate and lives in
// internal/api/admin/admin_floor_class_test.go's rawAuthorityReductionRe.

// carrierGuard is the scanner both tests below run, in one place so the
// non-vacuity test cannot end up proving a different configuration live than
// the one the real scan uses.
func carrierGuard() auditoutbox.Guard {
	return auditoutbox.Guard{Tables: []string{"platform_admins"}}
}

// TestCarrierMutationsRequireAnAuditIntentWriter fails the moment any function
// in this package writes platform_admins without taking an audit-intent writer
// — including a helper nobody thought to write a behavioural test for.
func TestCarrierMutationsRequireAnAuditIntentWriter(t *testing.T) {
	report, err := carrierGuard().ScanDir(".")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	// A scan that parsed nothing establishes nothing. ScanDir refuses an empty
	// directory outright; this asserts the count it reports is real, because a
	// glob that silently matched one file would otherwise read as a clean
	// package.
	if report.Files < 2 {
		t.Fatalf("scanned %d non-test source file(s) in this package — the scan is not looking at "+
			"what it thinks it is", report.Files)
	}
	for _, finding := range report.Findings {
		t.Errorf("%s: %s writes to %s but takes no audit-intent writer. "+
			"The highest privilege in the product must not be changeable without a record of the "+
			"change committing with it (issue #766, migration 000052). Route it through "+
			"platformadmin.Carrier, which takes the writer as a mandatory parameter.",
			finding.Position, finding.Func, finding.Table)
	}
	// The carrier mutations themselves are the library's now, so this package
	// is expected to hold none of its own. Asserted rather than assumed: if one
	// appears, the loop above is what has to catch it, and that is what
	// TestCarrierMutationGuardIsLive proves it can do.
	if report.Mutators != 0 {
		t.Errorf("found %d function(s) writing platform_admins in this package; the mechanism is "+
			"platformadmin.Carrier and this package should hold none", report.Mutators)
	}
}

// TestCarrierMutationGuardIsLive is the non-vacuity half, and the reason the
// test above can assert zero mutators without becoming decoration.
//
// It points the SAME guard at a fixture that does mutate the carrier — one
// function unaudited, one audited, both with the SQL hoisted into a
// package-level const — and requires it to report exactly the unaudited one.
// A guard that stopped matching (a renamed table, a changed SQL idiom, a scan
// that no longer resolves consts) fails here rather than reporting a clean
// package forever.
func TestCarrierMutationGuardIsLive(t *testing.T) {
	report, err := carrierGuard().ScanDir(filepath.Join("testdata", "carrier_mutations"))
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if report.Mutators != 2 {
		t.Fatalf("Mutators = %d, want 2 (the fixture's audited and unaudited carrier writes); "+
			"the scan no longer recognises the estate's SQL idiom", report.Mutators)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %v, want exactly one: the unaudited PurgeAdmin", report.Findings)
	}
	if got := report.Findings[0].Func; got != "(receiver).PurgeAdmin" {
		t.Errorf("finding = %q, want %q", got, "(receiver).PurgeAdmin")
	}
	if got := report.Findings[0].Table; got != "platform_admins" {
		t.Errorf("finding table = %q, want %q", got, "platform_admins")
	}
}

// TestCarrierMutationGuardRefusesAnEmptyUniverse pins the other way a source
// scan reads as protection while protecting nothing: no protected tables at
// all. The library refuses it with ErrGuard rather than returning an empty,
// passing report.
func TestCarrierMutationGuardRefusesAnEmptyUniverse(t *testing.T) {
	_, err := auditoutbox.Guard{}.ScanDir(".")
	if !errors.Is(err, auditoutbox.ErrGuard) {
		t.Fatalf("err = %v, want auditoutbox.ErrGuard: a guard with nothing to protect must refuse "+
			"rather than pass", err)
	}
}
