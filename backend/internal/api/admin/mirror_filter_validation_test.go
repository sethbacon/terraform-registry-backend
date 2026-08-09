package admin

import (
	"fmt"
	"strings"
	"testing"
)

// Issue #752 — the mirror config's namespace_filter / provider_filter reach the
// storage key unvalidated.
//
// jobs/mirror_sync.go builds the object key as
//
//	fmt.Sprintf("providers/%s/%s/%s/%s/%s/%s",
//	    namespace, providerName, version, platform.OS, platform.Arch, filename)
//
// and a comment there asserted the segments other than filename are "validated
// registry identifiers / platform values". That was true of the upload paths,
// which run ValidateRegistrySegment, and NOT true of these two: they arrived
// from admin-supplied JSON via the mirror API and were unmarshalled straight
// into the loop.
//
// So an admin could put "../.." in a provider filter and steer the key. On
// S3/GCS/Azure that writes a confusable object key; on local storage safeJoin
// rejects it, meaning the same configuration behaves differently per backend.
// The filter values also go into the upstream registry request path.

// traversalFilters are the values that must be refused. They are the ones that
// change where an artifact lands, not merely odd-looking ones.
var traversalFilters = []string{
	"../..",
	"../../etc",
	"..",
	"a/b",
	"a/../b",
	"/absolute",
	`back\slash`,
	"has space",
	"UPPER", // ValidateRegistrySegment is lowercase-only
	"-leading-hyphen",
	"",
}

// TestValidateMirrorFilters_RejectsTraversal drives the shared helper both
// handlers use.
func TestValidateMirrorFilters_RejectsTraversal(t *testing.T) {
	for _, bad := range traversalFilters {
		t.Run(fmt.Sprintf("namespace=%q", bad), func(t *testing.T) {
			if err := validateMirrorFilters([]string{bad}, nil); err == nil {
				t.Errorf("namespace filter %q was accepted; it is interpolated into the "+
					"storage key and the upstream request path", bad)
			} else if !strings.Contains(err.Error(), "namespace_filter") {
				t.Errorf("error = %q, want it to name the offending field", err)
			}
		})
		t.Run(fmt.Sprintf("provider=%q", bad), func(t *testing.T) {
			if err := validateMirrorFilters(nil, []string{bad}); err == nil {
				t.Errorf("provider filter %q was accepted", bad)
			} else if !strings.Contains(err.Error(), "provider_filter") {
				t.Errorf("error = %q, want it to name the offending field", err)
			}
		})
	}
}

// TestValidateMirrorFilters_AcceptsRealRegistryNames is the other direction: a
// validator that rejects ordinary provider names would make mirroring unusable
// and get removed.
func TestValidateMirrorFilters_AcceptsRealRegistryNames(t *testing.T) {
	namespaces := []string{"hashicorp", "integrations", "acme_corp", "my-org", "a", "0org"}
	providers := []string{"aws", "azurerm", "google", "terraform-provider-foo", "vault", "my_provider"}

	if err := validateMirrorFilters(namespaces, providers); err != nil {
		t.Errorf("a realistic filter set was rejected: %v", err)
	}
}

// TestValidateMirrorFilters_ChecksBothFields — validating one field and not the
// other leaves the unvalidated one as the way in. Both are interpolated into
// the same key.
func TestValidateMirrorFilters_ChecksBothFields(t *testing.T) {
	if err := validateMirrorFilters([]string{"hashicorp"}, []string{"../.."}); err == nil {
		t.Error("a valid namespace with a traversing provider filter was accepted")
	}
	if err := validateMirrorFilters([]string{"../.."}, []string{"aws"}); err == nil {
		t.Error("a traversing namespace with a valid provider filter was accepted")
	}
}

// TestMirrorKeyShape_IsWhatTheFiltersSteer documents the consequence the
// validation prevents, using the same format string as mirror_sync.
//
// It asserts the traversal is REAL rather than hypothetical: with the filter
// values spliced in unvalidated, the resulting key escapes the providers/
// prefix entirely.
func TestMirrorKeyShape_IsWhatTheFiltersSteer(t *testing.T) {
	key := fmt.Sprintf("providers/%s/%s/%s/%s/%s/%s",
		"hashicorp", "../../..", "1.0.0", "linux", "amd64", "x.zip")

	if !strings.Contains(key, "../../..") {
		t.Fatalf("key = %q, expected the unvalidated filter to appear verbatim", key)
	}
	// The point: this is not a providers/ key any more.
	if cleaned := cleanKey(key); strings.HasPrefix(cleaned, "providers/") {
		t.Errorf("key %q cleans to %q, which is still under providers/ — pick a "+
			"traversal deep enough to demonstrate the escape", key, cleaned)
	}
}

// cleanKey is path.Clean, spelled out to keep this test free of a dependency on
// the storage package (which is what consumes the key).
func cleanKey(k string) string {
	parts := strings.Split(k, "/")
	var out []string
	for _, p := range parts {
		switch p {
		case ".", "":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, p)
		}
	}
	return strings.Join(out, "/")
}
