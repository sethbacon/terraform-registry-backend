// filter_test.go tests the version-filtering helpers in the mirror package.
package mirror

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeVersions(vs ...string) []ProviderVersion {
	out := make([]ProviderVersion, len(vs))
	for i, v := range vs {
		out[i] = ProviderVersion{Version: v}
	}
	return out
}

func versionNames(versions []ProviderVersion) []string {
	out := make([]string, len(versions))
	for i, v := range versions {
		out[i] = v.Version
	}
	return out
}

// ---------------------------------------------------------------------------
// FilterVersions — nil / empty filter
// ---------------------------------------------------------------------------

func TestFilterVersions_NilFilter(t *testing.T) {
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := FilterVersions(versions, nil)
	if len(got) != 3 {
		t.Errorf("nil filter: len = %d, want 3", len(got))
	}
}

func TestFilterVersions_EmptyFilter(t *testing.T) {
	empty := ""
	versions := makeVersions("1.0.0", "2.0.0")
	got := FilterVersions(versions, &empty)
	if len(got) != 2 {
		t.Errorf("empty filter: len = %d, want 2", len(got))
	}
}

// ---------------------------------------------------------------------------
// FilterVersions — latest:N
// ---------------------------------------------------------------------------

func TestFilterVersions_LatestN(t *testing.T) {
	f := "latest:2"
	versions := makeVersions("1.0.0", "3.0.0", "2.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 2 {
		t.Fatalf("latest:2: len = %d, want 2", len(got))
	}
	names := versionNames(got)
	// Should be the 2 highest: 3.0.0 and 2.0.0
	found300, found200 := false, false
	for _, n := range names {
		if n == "3.0.0" {
			found300 = true
		}
		if n == "2.0.0" {
			found200 = true
		}
	}
	if !found300 || !found200 {
		t.Errorf("latest:2 got %v, want 3.0.0 and 2.0.0", names)
	}
}

func TestFilterVersions_LatestN_FewerThanN(t *testing.T) {
	f := "latest:10"
	versions := makeVersions("1.0.0", "2.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 2 {
		t.Errorf("latest:10 with 2 versions: len = %d, want 2", len(got))
	}
}

func TestFilterVersions_LatestN_InvalidN(t *testing.T) {
	f := "latest:abc"
	versions := makeVersions("1.0.0", "2.0.0")
	got := FilterVersions(versions, &f)
	// Invalid N falls back to all versions
	if len(got) != 2 {
		t.Errorf("latest:abc: len = %d, want 2 (all)", len(got))
	}
}

func TestFilterVersions_LatestN_ZeroN(t *testing.T) {
	f := "latest:0"
	versions := makeVersions("1.0.0")
	got := FilterVersions(versions, &f)
	// count <= 0 → falls back to all
	if len(got) != 1 {
		t.Errorf("latest:0: len = %d, want 1 (all)", len(got))
	}
}

// ---------------------------------------------------------------------------
// FilterVersions — prefix (X. or X.x)
// ---------------------------------------------------------------------------

func TestFilterVersions_DotPrefix(t *testing.T) {
	f := "3."
	versions := makeVersions("3.0.0", "3.1.0", "2.0.0", "4.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 2 {
		t.Errorf("prefix 3.: len = %d, want 2: %v", len(got), versionNames(got))
	}
}

func TestFilterVersions_DotXPrefix(t *testing.T) {
	f := "3.x"
	versions := makeVersions("3.0.0", "3.99.0", "2.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 2 {
		t.Errorf("prefix 3.x: len = %d, want 2: %v", len(got), versionNames(got))
	}
}

// ---------------------------------------------------------------------------
// FilterVersions — comma-separated list
// ---------------------------------------------------------------------------

func TestFilterVersions_CommaList(t *testing.T) {
	f := "1.0.0,3.0.0"
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0", "4.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 2 {
		t.Errorf("comma list: len = %d, want 2: %v", len(got), versionNames(got))
	}
}

func TestFilterVersions_CommaList_NoneMatch(t *testing.T) {
	f := "9.9.9,8.8.8"
	versions := makeVersions("1.0.0", "2.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 0 {
		t.Errorf("no-match comma list: len = %d, want 0", len(got))
	}
}

// ---------------------------------------------------------------------------
// FilterVersions — semver constraints
// ---------------------------------------------------------------------------

func TestFilterVersions_GreaterThanOrEqual(t *testing.T) {
	f := ">=2.0.0"
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 2 {
		t.Errorf(">=2.0.0: len = %d, want 2: %v", len(got), versionNames(got))
	}
}

func TestFilterVersions_GreaterThan(t *testing.T) {
	f := ">2.0.0"
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 1 {
		t.Errorf(">2.0.0: len = %d, want 1: %v", len(got), versionNames(got))
	}
}

func TestFilterVersions_LessThanOrEqual(t *testing.T) {
	f := "<=2.0.0"
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 2 {
		t.Errorf("<=2.0.0: len = %d, want 2: %v", len(got), versionNames(got))
	}
}

func TestFilterVersions_LessThan(t *testing.T) {
	f := "<2.0.0"
	versions := makeVersions("1.0.0", "2.0.0", "3.0.0")
	got := FilterVersions(versions, &f)
	if len(got) != 1 {
		t.Errorf("<2.0.0: len = %d, want 1: %v", len(got), versionNames(got))
	}
}

// ---------------------------------------------------------------------------
// FilterVersions — bare version (tries prefix then list)
// ---------------------------------------------------------------------------

func TestFilterVersions_BareVersion_MatchesExact(t *testing.T) {
	f := "1.0.0"
	versions := makeVersions("1.0.0", "2.0.0", "1.0.0-beta")
	got := FilterVersions(versions, &f)
	// Prefix "1.0.0." matches nothing; list "1.0.0" matches "1.0.0" exactly
	if len(got) != 1 || got[0].Version != "1.0.0" {
		t.Errorf("bare 1.0.0: %v", versionNames(got))
	}
}

func TestFilterVersions_BareVersion_MatchesPrefix(t *testing.T) {
	f := "1.0"
	versions := makeVersions("1.0.0", "1.0.1", "2.0.0")
	got := FilterVersions(versions, &f)
	// "1.0" doesn't end in "." or ".x", no operators, no comma
	// Tries prefix "1.0." — matches "1.0.0" and "1.0.1"
	if len(got) != 2 {
		t.Errorf("bare 1.0: len = %d, want 2: %v", len(got), versionNames(got))
	}
}

// ---------------------------------------------------------------------------
// CompareSemver
// ---------------------------------------------------------------------------

func TestCompareSemver_Equal(t *testing.T) {
	if got := CompareSemver("1.2.3", "1.2.3"); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestCompareSemver_LessThan(t *testing.T) {
	if got := CompareSemver("1.2.3", "1.2.4"); got != -1 {
		t.Errorf("expected -1, got %d", got)
	}
}

func TestCompareSemver_GreaterThan(t *testing.T) {
	if got := CompareSemver("2.0.0", "1.99.99"); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
}

func TestCompareSemver_WithVPrefix(t *testing.T) {
	if got := CompareSemver("v1.2.3", "v1.2.3"); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestCompareSemver_WithPreRelease(t *testing.T) {
	// pre-release suffix stripped: "1.2.3-alpha" → "1.2.3"
	if got := CompareSemver("1.2.3-alpha", "1.2.3"); got != 0 {
		t.Errorf("expected 0 after stripping pre-release, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// parseSemverParts
// ---------------------------------------------------------------------------

func TestParseSemverParts_Full(t *testing.T) {
	got := parseSemverParts("1.2.3")
	want := [3]int{1, 2, 3}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseSemverParts_WithVPrefix(t *testing.T) {
	got := parseSemverParts("v1.2.3")
	want := [3]int{1, 2, 3}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseSemverParts_MajorMinorOnly(t *testing.T) {
	got := parseSemverParts("1.2")
	want := [3]int{1, 2, 0}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseSemverParts_MajorOnly(t *testing.T) {
	got := parseSemverParts("5")
	if got[0] != 5 || got[1] != 0 || got[2] != 0 {
		t.Errorf("got %v, want [5,0,0]", got)
	}
}

func TestParseSemverParts_WithPreRelease(t *testing.T) {
	got := parseSemverParts("1.2.3-beta.1")
	want := [3]int{1, 2, 3}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
