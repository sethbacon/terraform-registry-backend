package api

import "testing"

func TestCanonicalHostSet(t *testing.T) {
	got := canonicalHostSet(
		"https://registry.example.com",                         // public
		"http://registry.internal:8080",                        // base (distinct host)
		[]string{"tf.example.com", "REGISTRY.example.com", ""}, // alias + dup-of-public + empty
	)
	want := []string{"registry.example.com", "registry.internal:8080", "tf.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (order: public, base, aliases; deduped; empties dropped)", got, want)
		}
	}
}

// TestCanonicalHostSet_PublicOnly: the default deploy (public_url empty → base
// used; no aliases) yields exactly one host and never an empty set.
func TestCanonicalHostSet_PublicOnly(t *testing.T) {
	got := canonicalHostSet("http://localhost:8080", "http://localhost:8080", nil)
	if len(got) != 1 || got[0] != "localhost:8080" {
		t.Fatalf("got %v, want [localhost:8080]", got)
	}
}
