package api

import "testing"

func TestCanonicalHost(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "reg.example.com", "reg.example.com"},
		{"uppercase", "REG.Example.COM", "reg.example.com"},
		{"trailing dot", "reg.example.com.", "reg.example.com"},
		{"default https port stripped", "reg.example.com:443", "reg.example.com"},
		{"default http port stripped", "reg.example.com:80", "reg.example.com"},
		{"non-default port preserved", "reg.example.com:8443", "reg.example.com:8443"},
		{"scheme stripped", "https://reg.example.com/", "reg.example.com"},
		{"scheme + default port", "https://REG.Example.com.:443/v1/modules/", "reg.example.com"},
		{"scheme + non-default port", "http://reg.example.com:8080", "reg.example.com:8080"},
		{"surrounding whitespace", "  reg.example.com  ", "reg.example.com"},
		{"ipv4", "10.0.0.5", "10.0.0.5"},
		{"ipv4 with port", "10.0.0.5:8443", "10.0.0.5:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalHost(tc.in); got != tc.want {
				t.Errorf("canonicalHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCanonicalHost_Idempotent guards the join invariant: applying the function
// twice must equal applying it once, so re-canonicalizing an already-stored host
// never drifts.
func TestCanonicalHost_Idempotent(t *testing.T) {
	for _, in := range []string{"reg.example.com", "REG.Example.com:443", "https://reg.example.com:8080"} {
		once := canonicalHost(in)
		if twice := canonicalHost(once); twice != once {
			t.Errorf("not idempotent: canonicalHost(%q)=%q then %q", in, once, twice)
		}
	}
}

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
