package mirror

import "testing"

func TestIsUnsignedUpstreamTool(t *testing.T) {
	// OPA is unsigned upstream; matching is case-insensitive and trims space.
	for _, tool := range []string{"opa", "OPA", "Opa", " opa "} {
		if !IsUnsignedUpstreamTool(tool) {
			t.Errorf("IsUnsignedUpstreamTool(%q) = false, want true", tool)
		}
	}
	// Key-managed tools and unclassified/empty values are not unsigned-upstream.
	for _, tool := range []string{"terraform", "opentofu", "packer", "sentinel", "custom", ""} {
		if IsUnsignedUpstreamTool(tool) {
			t.Errorf("IsUnsignedUpstreamTool(%q) = true, want false", tool)
		}
	}
}
