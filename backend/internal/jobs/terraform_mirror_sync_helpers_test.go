package jobs

import (
	"testing"
)

// ---------------------------------------------------------------------------
// productNameForTool
// ---------------------------------------------------------------------------

func TestProductNameForTool_Terraform(t *testing.T) {
	if got := productNameForTool("terraform"); got != "terraform" {
		t.Errorf("got %q, want %q", got, "terraform")
	}
}

func TestProductNameForTool_TerraformUpperCase(t *testing.T) {
	if got := productNameForTool("Terraform"); got != "terraform" {
		t.Errorf("got %q, want %q", got, "terraform")
	}
}

func TestProductNameForTool_OpenTofu(t *testing.T) {
	if got := productNameForTool("opentofu"); got != "opentofu" {
		t.Errorf("got %q, want %q", got, "opentofu")
	}
}

func TestProductNameForTool_OpenTofuUpperCase(t *testing.T) {
	if got := productNameForTool("OpenTofu"); got != "opentofu" {
		t.Errorf("got %q, want %q", got, "opentofu")
	}
}

func TestProductNameForTool_Unknown(t *testing.T) {
	if got := productNameForTool("other"); got != "terraform" {
		t.Errorf("got %q, want %q", got, "terraform")
	}
}

// ---------------------------------------------------------------------------
// gpgKeyForTool
// ---------------------------------------------------------------------------

func TestGPGKeyForTool_Terraform(t *testing.T) {
	key := gpgKeyForTool("terraform")
	if key == "" {
		t.Error("expected non-empty GPG key for terraform")
	}
}

func TestGPGKeyForTool_TerraformUpperCase(t *testing.T) {
	key := gpgKeyForTool("Terraform")
	if key == "" {
		t.Error("expected non-empty GPG key for Terraform (case insensitive)")
	}
}

func TestGPGKeyForTool_Unknown(t *testing.T) {
	key := gpgKeyForTool("something-else")
	if key != "" {
		t.Errorf("expected empty key for unknown tool, got non-empty")
	}
}

// ---------------------------------------------------------------------------
// hasPreReleaseSuffix
// ---------------------------------------------------------------------------

func TestHasPreReleaseSuffix_Stable(t *testing.T) {
	for _, v := range []string{"1.9.0", "v1.9.0", "1.0.0", "2.0.1"} {
		if hasPreReleaseSuffix(v) {
			t.Errorf("hasPreReleaseSuffix(%q) = true, want false", v)
		}
	}
}

func TestHasPreReleaseSuffix_PreRelease(t *testing.T) {
	for _, v := range []string{"1.9.0-alpha1", "v1.9.0-beta", "1.0.0-rc1", "1.0.0+build.1"} {
		if !hasPreReleaseSuffix(v) {
			t.Errorf("hasPreReleaseSuffix(%q) = false, want true", v)
		}
	}
}

// ---------------------------------------------------------------------------
// splitSemver
// ---------------------------------------------------------------------------

func TestSplitSemver_Basic(t *testing.T) {
	got := splitSemver("1.9.5")
	want := [3]int{1, 9, 5}
	if got != want {
		t.Errorf("splitSemver(%q) = %v, want %v", "1.9.5", got, want)
	}
}

func TestSplitSemver_Zeros(t *testing.T) {
	got := splitSemver("0.0.0")
	want := [3]int{0, 0, 0}
	if got != want {
		t.Errorf("splitSemver(%q) = %v, want %v", "0.0.0", got, want)
	}
}

func TestSplitSemver_MajorOnly(t *testing.T) {
	got := splitSemver("2")
	if got[0] != 2 || got[1] != 0 || got[2] != 0 {
		t.Errorf("splitSemver(%q) = %v, want [2 0 0]", "2", got)
	}
}

// ---------------------------------------------------------------------------
// compareTerraformSemver
// ---------------------------------------------------------------------------

func TestCompareTerraformSemver_Equal(t *testing.T) {
	if got := compareTerraformSemver("1.9.0", "1.9.0"); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestCompareTerraformSemver_LessThan(t *testing.T) {
	if got := compareTerraformSemver("1.8.0", "1.9.0"); got != -1 {
		t.Errorf("expected -1, got %d", got)
	}
}

func TestCompareTerraformSemver_GreaterThan(t *testing.T) {
	if got := compareTerraformSemver("1.9.1", "1.9.0"); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
}

func TestCompareTerraformSemver_WithVPrefix(t *testing.T) {
	if got := compareTerraformSemver("v1.9.0", "v1.9.0"); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestCompareTerraformSemver_StripPreRelease(t *testing.T) {
	// Pre-release suffix stripped: 1.9.0-alpha vs 1.9.0 → equal on core
	if got := compareTerraformSemver("1.9.0-alpha", "1.9.0"); got != 0 {
		t.Errorf("expected 0 after stripping pre-release, got %d", got)
	}
}

func TestCompareTerraformSemver_MajorDifference(t *testing.T) {
	if got := compareTerraformSemver("2.0.0", "1.99.99"); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
}

func TestCompareTerraformSemver_PatchDifference(t *testing.T) {
	if got := compareTerraformSemver("1.5.2", "1.5.3"); got != -1 {
		t.Errorf("expected -1, got %d", got)
	}
}
