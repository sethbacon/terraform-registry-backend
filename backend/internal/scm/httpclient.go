// httpclient.go provides the shared HTTP client and response-body size caps used by all
// SCM connectors (GitHub, GitLab, Bitbucket Data Center, Azure DevOps) for API calls and
// OAuth token exchanges.
package scm

import (
	"io"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
)

// httpClientTimeout is the shared request timeout for all SCM connector calls.
const httpClientTimeout = 30 * time.Second

// HTTPClient is the shared HTTP client every SCM connector should use instead of
// http.DefaultClient, which has a zero Timeout. Self-hosted/enterprise SCM instance
// base URLs are operator-configurable, so every request is routed through the
// SSRF-safe egress client (internal/httpsafe): private/metadata targets are
// refused at dial time (resolve-and-pin) and redirects are re-validated per hop.
// The strict default policy applies until ConfigureEgress installs the
// operator's allow-list at startup; tests that talk to local httptest servers
// replace this client with one built from an explicit loopback allow-list.
var HTTPClient = httpsafe.NewClient(httpClientTimeout, nil)

// ConfigureEgress rebuilds the shared connector client with the
// operator-configured egress allow-list (security.egress.allowlist). Call once
// at startup before any connector traffic; entries may be hostnames, IPs, or
// CIDR ranges.
func ConfigureEgress(allowlist []string) error {
	g, err := httpsafe.NewGuard(allowlist)
	if err != nil {
		return err
	}
	HTTPClient = httpsafe.NewClient(httpClientTimeout, g)
	return nil
}

const (
	// MaxResponseBodyBytes bounds successful SCM API response bodies (repository
	// listings, commit/tag/branch metadata, OAuth token responses). These are small
	// JSON documents in legitimate use; the cap guards against a misbehaving or
	// adversarial SCM instance returning an unbounded body that would otherwise be
	// fully buffered in memory by io.ReadAll/json.Decode.
	MaxResponseBodyBytes = 10 << 20 // 10 MB

	// MaxErrorBodyBytes bounds non-2xx response bodies read only for inclusion in a
	// returned error message.
	MaxErrorBodyBytes = 4096
)

// LimitBody wraps r in an io.LimitReader capped at MaxResponseBodyBytes, for use before
// io.ReadAll or json.NewDecoder(...).Decode on a successful SCM API response body.
func LimitBody(r io.Reader) io.Reader {
	return io.LimitReader(r, MaxResponseBodyBytes)
}

// LimitErrorBody wraps r in an io.LimitReader capped at MaxErrorBodyBytes, for use before
// io.ReadAll on a non-2xx SCM API response consumed only for an error message.
func LimitErrorBody(r io.Reader) io.Reader {
	return io.LimitReader(r, MaxErrorBodyBytes)
}
