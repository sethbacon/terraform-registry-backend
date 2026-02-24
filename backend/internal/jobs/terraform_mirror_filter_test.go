package jobs

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/mirror"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeTFVersions(vs ...string) []mirror.TerraformVersionInfo {
	out := make([]mirror.TerraformVersionInfo, len(vs))
	for i, v := range vs {
		out[i] = mirror.TerraformVersionInfo{Version: v}
	}
	return out
}

func tfVersionNames(versions []mirror.TerraformVersionInfo) []string {
	out := make([]string, len(versions))
	for i, v := range versions {
		out[i] = v.Version
	}
	return out
}

func assertTFVersions(t *testing.T, got []mirror.TerraformVersionInfo, want ...string) {
	t.Helper()
	names := tfVersionNames(got)
	if len(names) != len(want) {
		t.Errorf("got versions %v, want %v", names, want)
		return
	}
	seen := make(map[string]bool, len(want))
	for _, w := range want {
		seen[w] = true
	}
	for _, g := range names {
		if !seen[g] {
			t.Errorf("unexpected version %q in result %v (want %v)", g, names, want)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// filterTerraformVersions – nil / empty filter
// ---------------------------------------------------------------------------

func TestFilterTerraformVersions_NilFilter(t *testing.T) {
	input := makeTFVersions("1.5.0", "1.6.0", "1.9.0")
	got := filterTerraformVersions(input, nil)
	if len(got) != 3 {
		t.Errorf("nil filter: got %d versions, want 3", len(got))
	}
}

func TestFilterTerraformVersions_EmptyFilter(t *testing.T) {
	input := makeTFVersions("1.5.0", "1.9.0")
	e := ""
	got := filterTerraformVersions(input, &e)
	if len(got) != 2 {
		t.Errorf("empty filter: got %d versions, want 2", len(got))
	}
}

func TestFilterTerraformVersions_WhitespaceFilter(t *testing.T) {
	input := makeTFVersions("1.5.0", "1.9.0")
	ws := "   "
	got := filterTerraformVersions(input, &ws)
	if len(got) != 2 {
		t.Errorf("whitespace-only filter: got %d versions, want 2", len(got))
	}
}

// ---------------------------------------------------------------------------
// filterTerraformVersions – latest:N
// ---------------------------------------------------------------------------

func TestFilterTerraformVersions_LatestN(t *testing.T) {
	input := makeTFVersions("1.5.0", "1.7.0", "1.9.0", "1.6.0")
	f := "latest:2"
	got := filterTerraformVersions(input, &f)
	if len(got) != 2 {
		t.Fatalf("latest:2 got %d versions: %v", len(got), tfVersionNames(got))
	}
	assertTFVersions(t, got, "1.9.0", "1.7.0")
}

func TestFilterTerraformVersions_LatestN_FewerThanN(t *testing.T) {
	input := makeTFVersions("1.5.0", "1.6.0")
	f := "latest:10"
	got := filterTerraformVersions(input, &f)
	if len(got) != 2 {
		t.Errorf("latest:10 with 2 versions: got %d, want 2", len(got))
	}
}

func TestFilterTerraformVersions_LatestInvalid(t *testing.T) {
	input := makeTFVersions("1.5.0", "1.9.0")
	f := "latest:abc"
	got := filterTerraformVersions(input, &f)
	if len(got) != 2 {
		t.Errorf("invalid latest:N should return all: got %d", len(got))
	}
}

func TestFilterTerraformVersions_LatestZero(t *testing.T) {
	input := makeTFVersions("1.5.0", "1.9.0")
	f := "latest:0"
	got := filterTerraformVersions(input, &f)
	if len(got) != 2 {
		t.Errorf("latest:0 should return all: got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// filterTerraformVersions – prefix (trailing dot / .x)
// ---------------------------------------------------------------------------

func TestFilterTerraformVersions_PrefixTrailingDot(t *testing.T) {
	input := makeTFVersions("1.9.0", "1.9.1", "1.10.0", "2.0.0")
	f := "1.9."
	got := filterTerraformVersions(input, &f)
	assertTFVersions(t, got, "1.9.0", "1.9.1")
}

func TestFilterTerraformVersions_PrefixDotX(t *testing.T) {
	input := makeTFVersions("1.9.0", "1.9.5", "2.0.0")
	f := "1.9.x"
	got := filterTerraformVersions(input, &f)
	assertTFVersions(t, got, "1.9.0", "1.9.5")
}

func TestFilterTerraformVersions_PrefixNoMatch(t *testing.T) {
	input := makeTFVersions("2.0.0", "2.1.0")
	f := "1.9."
	got := filterTerraformVersions(input, &f)
	if len(got) != 0 {
		t.Errorf("prefix with no match: got %d, want 0", len(got))
	}
}

// ---------------------------------------------------------------------------
// filterTerraformVersions – semver constraints
// ---------------------------------------------------------------------------

func TestFilterTerraformVersions_GTE(t *testing.T) {
	input := makeTFVersions("1.4.0", "1.5.0", "1.6.0", "2.0.0")
	f := ">=1.5.0"
	got := filterTerraformVersions(input, &f)
	assertTFVersions(t, got, "1.5.0", "1.6.0", "2.0.0")
}

func TestFilterTerraformVersions_GT(t *testing.T) {
	input := makeTFVersions("1.4.9", "1.5.0", "1.6.0")
	f := ">1.5.0"
	got := filterTerraformVersions(input, &f)
	assertTFVersions(t, got, "1.6.0")
}

func TestFilterTerraformVersions_LTE(t *testing.T) {
	input := makeTFVersions("1.3.0", "1.5.0", "1.5.1", "1.9.0")
	f := "<=1.5.0"
	got := filterTerraformVersions(input, &f)
	assertTFVersions(t, got, "1.3.0", "1.5.0")
}

func TestFilterTerraformVersions_LT(t *testing.T) {
	input := makeTFVersions("1.3.0", "1.5.0", "1.9.0")
	f := "<1.5.0"
	got := filterTerraformVersions(input, &f)
	assertTFVersions(t, got, "1.3.0")
}

// ---------------------------------------------------------------------------
// filterTerraformVersions – comma-separated list
// ---------------------------------------------------------------------------

func TestFilterTerraformVersions_CommaSeparated(t *testing.T) {
	input := makeTFVersions("1.5.0", "1.6.0", "1.7.0", "2.0.0")
	f := "1.5.0, 1.7.0"
	got := filterTerraformVersions(input, &f)
	assertTFVersions(t, got, "1.5.0", "1.7.0")
}

func TestFilterTerraformVersions_CommaSeparated_NoMatch(t *testing.T) {
	input := makeTFVersions("1.5.0", "1.6.0")
	f := "9.0.0,9.1.0"
	got := filterTerraformVersions(input, &f)
	if len(got) != 0 {
		t.Errorf("no-match list: got %d, want 0", len(got))
	}
}

// ---------------------------------------------------------------------------
// filterTerraformVersions – single token (prefix then exact)
// ---------------------------------------------------------------------------

func TestFilterTerraformVersions_SingleTokenPrefix(t *testing.T) {
	input := makeTFVersions("1.9.0", "1.9.1", "1.10.0")
	f := "1.9"
	got := filterTerraformVersions(input, &f)
	assertTFVersions(t, got, "1.9.0", "1.9.1")
}

func TestFilterTerraformVersions_SingleTokenExact(t *testing.T) {
	input := makeTFVersions("1.9.0", "1.9.1", "2.0.0")
	f := "1.9.0"
	got := filterTerraformVersions(input, &f)
	assertTFVersions(t, got, "1.9.0")
}

func TestFilterTerraformVersions_SingleTokenNoMatch(t *testing.T) {
	input := makeTFVersions("1.9.0", "2.0.0")
	f := "3.0.0"
	got := filterTerraformVersions(input, &f)
	if len(got) != 0 {
		t.Errorf("single no-match token: got %d, want 0", len(got))
	}
}

// ---------------------------------------------------------------------------
// filterTFLatest – already-sorted / edge cases
// ---------------------------------------------------------------------------

func TestFilterTFLatest_ExactlyN(t *testing.T) {
	input := makeTFVersions("1.0.0", "2.0.0")
	got := filterTFLatest(input, 2)
	if len(got) != 2 {
		t.Errorf("exactly N: got %d, want 2", len(got))
	}
}

func TestFilterTFLatest_SortOrder(t *testing.T) {
	input := makeTFVersions("1.0.0", "3.0.0", "2.0.0")
	got := filterTFLatest(input, 2)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].Version != "3.0.0" {
		t.Errorf("first should be 3.0.0, got %q", got[0].Version)
	}
	if got[1].Version != "2.0.0" {
		t.Errorf("second should be 2.0.0, got %q", got[1].Version)
	}
}

// ---------------------------------------------------------------------------
// filterTFBySemver – default / unknown op guard
// ---------------------------------------------------------------------------

func TestFilterTFBySemver_UnknownOp(t *testing.T) {
	input := makeTFVersions("1.0.0", "2.0.0")
	// Pass a string that doesn't start with any known op character — hits `default:`.
	got := filterTFBySemver(input, "~1.0.0")
	if len(got) != 2 {
		t.Errorf("unknown op should return all: got %d", len(got))
	}
}
