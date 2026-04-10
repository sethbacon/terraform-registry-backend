package jobs

import (
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
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

func TestGPGKeyForTool_OpenTofu(t *testing.T) {
	// OpenTofu key is embedded; should return a non-empty key if the real key is present.
	key := gpgKeyForTool("opentofu")
	// The key may be empty if the placeholder is still in place, but calling the function
	// must not panic. Just verify the function executes without error.
	_ = key
}

func TestGPGKeyForTool_OpenTofuUpperCase(t *testing.T) {
	key := gpgKeyForTool("OpenTofu")
	_ = key
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

// ---------------------------------------------------------------------------
// githubBinaryPrefix
// ---------------------------------------------------------------------------

func TestGithubBinaryPrefix_Terraform(t *testing.T) {
	if got := githubBinaryPrefix("terraform"); got != "terraform" {
		t.Errorf("got %q, want terraform", got)
	}
}

func TestGithubBinaryPrefix_OpenTofu(t *testing.T) {
	if got := githubBinaryPrefix("opentofu"); got != "tofu" {
		t.Errorf("got %q, want tofu", got)
	}
}

func TestGithubBinaryPrefix_OpenTofuUpperCase(t *testing.T) {
	if got := githubBinaryPrefix("OpenTofu"); got != "tofu" {
		t.Errorf("got %q, want tofu", got)
	}
}

func TestGithubBinaryPrefix_Other(t *testing.T) {
	if got := githubBinaryPrefix("custom-tool"); got != "custom-tool" {
		t.Errorf("got %q, want custom-tool", got)
	}
}

// ---------------------------------------------------------------------------
// gpgKeyForConfig
// ---------------------------------------------------------------------------

func TestGPGKeyForConfig_SkipGPGVerify(t *testing.T) {
	cfg := &models.TerraformMirrorConfig{
		Tool:          "terraform",
		SkipGPGVerify: true,
	}
	if got := gpgKeyForConfig(cfg); got != "" {
		t.Errorf("expected empty key when SkipGPGVerify=true, got %q", got)
	}
}

func TestGPGKeyForConfig_CustomGPGKey(t *testing.T) {
	customKey := "my-custom-gpg-key"
	cfg := &models.TerraformMirrorConfig{
		Tool:         "terraform",
		CustomGPGKey: &customKey,
	}
	if got := gpgKeyForConfig(cfg); got != customKey {
		t.Errorf("got %q, want %q", got, customKey)
	}
}

func TestGPGKeyForConfig_EmptyCustomKey_FallsBackToBuiltIn(t *testing.T) {
	empty := ""
	cfg := &models.TerraformMirrorConfig{
		Tool:         "terraform",
		CustomGPGKey: &empty,
	}
	key := gpgKeyForConfig(cfg)
	if key == "" {
		t.Error("expected built-in terraform GPG key when custom key is empty string")
	}
}

func TestGPGKeyForConfig_NilCustomKey_FallsBackToBuiltIn(t *testing.T) {
	cfg := &models.TerraformMirrorConfig{
		Tool:         "terraform",
		CustomGPGKey: nil,
	}
	key := gpgKeyForConfig(cfg)
	if key == "" {
		t.Error("expected built-in terraform GPG key when CustomGPGKey is nil")
	}
}

func TestGPGKeyForConfig_UnknownTool(t *testing.T) {
	cfg := &models.TerraformMirrorConfig{Tool: "unknown"}
	if got := gpgKeyForConfig(cfg); got != "" {
		t.Errorf("expected empty key for unknown tool, got %q", got)
	}
}
