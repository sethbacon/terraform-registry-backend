package api

import "github.com/sethbacon/terraform-suite-identity/identity/suite"

// canonicalHostSet builds the de-duplicated set of canonical host identities
// this registry presents for the suite "Consumed by" join: its public-URL host,
// its base-URL host, and any operator-configured aliases (vanity CNAMEs,
// split-horizon DNS, or a portless variant of a non-default-port public URL).
// Empty/unparseable entries are dropped. Including both the public and base
// hosts heals the common reverse-proxy case where authors still address the
// base host even though public_url is set.
//
// Hosts are normalized with the shared suite.CanonicalHost so the set compares
// like-for-like against the host the State Manager captured.
func canonicalHostSet(publicURL, baseURL string, aliases []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(raw string) {
		ch := suite.CanonicalHost(raw)
		if ch == "" {
			return
		}
		if _, dup := seen[ch]; dup {
			return
		}
		seen[ch] = struct{}{}
		out = append(out, ch)
	}
	add(publicURL)
	add(baseURL)
	for _, a := range aliases {
		add(a)
	}
	return out
}
