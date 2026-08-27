package repositories

// version_approval_coverage_test.go makes the reach of the version-approval
// gate a DECLARED fact rather than something a reader has to infer from three
// SQL constants (#975).
//
// WHY. The gate is described as the control over what may be consumed. It is
// narrower than that: it covers mirrored providers, mirrored Terraform/OpenTofu
// binaries and scanner binaries -- upstream content only. Locally uploaded
// provider versions are ungated by design, and modules have no approval
// concept anywhere in the schema.
//
// That is defensible: the gate exists to vet what arrives from OUTSIDE, and a
// module published to this registry came from a person who already had publish
// rights under a claimed namespace. But it was only inferable by reading the
// queries, and docs/threat-model.md was citing "upload approvals" as a
// mitigation for a control that does not exist.
//
// This file pins the reach in both directions: an artifact table that gains an
// approval_status column and is not enforced fails, and a table declared
// ungated that quietly gains a gate fails too.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// gatedTables are the tables the version-approval gate reads and enforces.
//
// Each must appear in the repository's queries -- asserted, so a branch deleted
// from the UNION stops being claimed as covered.
var gatedTables = map[string]string{
	"mirrored_provider_versions": "provider versions pulled from an upstream mirror",
	"terraform_versions":         "Terraform/OpenTofu binary versions pulled from an upstream mirror",
	"scanner_binary_versions":    "security scanner binaries downloaded from their vendor",
}

// unionBranch names the query constant that puts each gated table into the
// admin queue.
//
// Checked per-branch rather than "the table is mentioned somewhere in the
// file", which was provably too weak: each of these tables also appears in a
// COUNT query and an UPDATE, so removing a table from the UNION -- the change
// that makes its versions vanish from the queue -- left two other matches and
// the guard green.
var unionBranch = map[string]string{
	"mirrored_provider_versions": "providerSelect",
	"terraform_versions":         "terraformSelect",
	"scanner_binary_versions":    "scannerSelect",
}

// ungatedArtifactTables are the artifact tables a reader might reasonably expect
// the gate to cover, and the reason it does not.
//
// Recorded because "no approval column" is an absence, and an absence cannot be
// distinguished from an oversight. Naming them turns "modules are not gated"
// into a statement someone decided rather than one nobody noticed.
var ungatedArtifactTables = map[string]string{
	"modules": "no approval concept exists for modules anywhere in the schema. A module published " +
		"here came from a principal that already held publish rights under a claimed namespace, " +
		"so the gate's question -- should this UPSTREAM artifact be trusted -- does not arise. " +
		"Whether modules should have an approval concept at all is an open product question (#975).",
	"module_versions": "as above; the approval concept, if one is ever added, would live here.",
	"provider_versions": "locally UPLOADED provider versions are ungated by design: " +
		"GetVersionApprovalStatus returns nil when no mirrored row exists, and callers treat nil " +
		"as visible. Only the mirrored tracking row carries a verdict.",
}

// notAVersionGate are tables carrying an approval_status column that is not part
// of this gate at all.
var notAVersionGate = map[string]string{
	"mirror_configurations": "approves the MIRROR CONFIGURATION, not a version, and uses a " +
		"different vocabulary ('not_required'/'pending'/'approved'/'rejected') from the version " +
		"gate's ('pending_approval'/'approved'/'rejected'). Sharing a column name is the only " +
		"thing these two have in common.",
}

// TestApprovalGateCoversExactlyTheDeclaredTables reads the migrations for
// every table carrying an approval_status column and requires each to be
// classified.
func TestApprovalGateCoversExactlyTheDeclaredTables(t *testing.T) {
	withColumn := tablesWithApprovalStatus(t)

	if len(withColumn) < len(gatedTables) {
		t.Fatalf("found only %d tables with an approval_status column (%v); the migrations are not "+
			"being read, so this test is vacuous", len(withColumn), keysOf(withColumn))
	}

	for table := range withColumn {
		_, gated := gatedTables[table]
		_, other := notAVersionGate[table]
		if !gated && !other {
			t.Errorf("table %q has an approval_status column but is neither enforced by the "+
				"version-approval gate nor declared as something else.\n"+
				"An artifact that records a verdict nobody reads is worse than one with no verdict: "+
				"the admin queue implies a control that is not applied (#975).", table)
		}
	}

	// No stale claims: a gated table that lost its column, or was renamed.
	for table := range gatedTables {
		if !withColumn[table] {
			t.Errorf("gatedTables claims %q is gated, but no migration gives it an approval_status "+
				"column. Renamed, or the gate lost it?", table)
		}
	}
	for table := range notAVersionGate {
		if !withColumn[table] {
			t.Errorf("notAVersionGate names %q, which has no approval_status column at all", table)
		}
	}

	// And an ungated table must not quietly acquire one without moving lists.
	for table := range ungatedArtifactTables {
		if withColumn[table] {
			t.Errorf("table %q is declared ungated but now HAS an approval_status column.\n"+
				"Either it is gated now -- move it to gatedTables and make sure something enforces "+
				"it -- or the column is decorative, which is the worse of the two.", table)
		}
	}
}

// TestGatedTablesAreActuallyQueried closes the gap between declaring a table
// gated and the gate reading it.
//
// A branch removed from the UNION would otherwise leave gatedTables asserting a
// coverage that had silently stopped: the admin queue would just show fewer
// rows, which looks like a quiet week rather than a broken control.
func TestGatedTablesAreActuallyQueried(t *testing.T) {
	src, err := os.ReadFile("version_approval_repository.go")
	if err != nil {
		t.Fatalf("read version_approval_repository.go: %v", err)
	}
	body := string(src)
	for table, why := range gatedTables {
		constName, ok := unionBranch[table]
		if !ok {
			t.Errorf("gatedTables lists %q with no unionBranch entry, so nothing checks that the "+
				"admin queue actually reads it", table)
			continue
		}
		branch, found := constBody(body, constName)
		if !found {
			t.Errorf("query constant %q was not found. If the union was restructured, point "+
				"unionBranch at the new constant -- do not drop the entry, it is what keeps %q "+
				"from silently leaving the queue.", constName, table)
			continue
		}
		if !regexp.MustCompile(`FROM\s+` + regexp.QuoteMeta(table) + `\b`).MatchString(branch) {
			t.Errorf("gatedTables claims %q is enforced (%s), but %s does not select FROM it.\n"+
				"Those versions would stop appearing in the admin queue, which looks like a quiet "+
				"week rather than a broken control.", table, why, constName)
		}
	}
}

// constBody returns the raw-string literal assigned to the named constant.
//
// Scoped to the one constant on purpose: the whole-file search this replaces
// matched the COUNT and UPDATE statements too, so it could not tell "this table
// is in the queue" from "this table is mentioned".
func constBody(src, name string) (string, bool) {
	i := strings.Index(src, "const "+name+" = `")
	if i < 0 {
		return "", false
	}
	start := i + len("const "+name+" = `")
	end := strings.Index(src[start:], "`")
	if end < 0 {
		return "", false
	}
	return src[start : start+end], true
}

// tablesWithApprovalStatus returns every table a migration gives an
// approval_status column, whether at CREATE or by ALTER.
func tablesWithApprovalStatus(t *testing.T) map[string]bool {
	t.Helper()
	dir := filepath.Join("..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}

	createRe := regexp.MustCompile(`(?is)CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+([a-z_][a-z0-9_]*)\s*\((.*?)\n\);`)
	alterRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+([a-z_][a-z0-9_]*)\s+ADD\s+COLUMN(?:\s+IF\s+NOT\s+EXISTS)?\s+approval_status\b`)

	out := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- test-only, directory listing
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		sql := string(b)
		for _, m := range createRe.FindAllStringSubmatch(sql, -1) {
			if regexp.MustCompile(`(?im)^\s*approval_status\b`).MatchString(m[2]) {
				out[m[1]] = true
			}
		}
		for _, m := range alterRe.FindAllStringSubmatch(sql, -1) {
			out[m[1]] = true
		}
	}
	return out
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
