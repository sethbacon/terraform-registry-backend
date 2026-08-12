// httpclient.go provides the shared HTTP client, response-body size caps, and the two
// request helpers (DoJSON, ExchangeOAuthForm) used by all SCM connectors (GitHub, GitLab,
// Bitbucket Data Center, Azure DevOps) for API calls and OAuth token exchanges.
package scm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// DoJSON sends req through the shared SSRF-safe egress client (HTTPClient) and decodes a
// 200 OK JSON response body into out.
//
// The caller builds req, so the method, URL, and headers — including the Authorization
// header — stay entirely under the caller's control. DoJSON owns only the part every
// connector repeats identically: routing through HTTPClient (never a bare http.Client,
// which would bypass the egress guard), closing the body, mapping the response status
// onto an error, and size-capping the decoded body with LimitBody.
//
// reason is the message carried by the *APIError returned for a transport failure
// (StatusCode 0, wrapping the transport error) or for an unexpected status. Passing a
// non-nil notFound makes HTTP 404 return that sentinel verbatim, so each call site keeps
// its own (ErrRepoNotFound, ErrTagNotFound, ErrCommitNotFound); pass nil where 404 has no
// special meaning. Response bodies are never copied into the returned error: an SCM
// response can carry repository content and these errors reach registry API clients.
func DoJSON(req *http.Request, reason string, notFound error, out any) error {
	// #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return WrapRemoteError(0, reason, err)
	}
	defer resp.Body.Close()

	if notFound != nil && resp.StatusCode == http.StatusNotFound {
		return notFound
	}
	if resp.StatusCode != http.StatusOK {
		return WrapRemoteError(resp.StatusCode, reason, nil)
	}

	if err := json.NewDecoder(LimitBody(resp.Body)).Decode(out); err != nil {
		return fmt.Errorf("%s: decode response: %w", reason, err)
	}
	return nil
}

// ExchangeOAuthForm posts form to tokenURL as application/x-www-form-urlencoded through
// the shared SSRF-safe egress client and decodes the JSON token response into out. It is
// the OAuth authorization-code exchange shared by the GitHub, GitLab, and Azure DevOps
// (Microsoft Entra ID) connectors.
//
// acceptHeader, when non-empty, is sent as the Accept request header. GitHub returns a
// form-encoded token response unless the caller asks for JSON, whereas GitLab and Entra ID
// return JSON regardless and send no Accept header — so the header stays a caller
// decision rather than something this helper imposes on every provider.
//
// Unlike DoJSON, a non-200 response here carries a size-capped snippet of the response
// body (LimitErrorBody) in the returned *APIError: the OAuth error body is the provider's
// machine-readable failure reason (invalid_client, redirect_uri_mismatch, ...) and is what
// makes a misconfigured app registration diagnosable.
func ExchangeOAuthForm(ctx context.Context, tokenURL string, form url.Values, acceptHeader string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create token request: %w", err)
	}
	if acceptHeader != "" {
		req.Header.Set("Accept", acceptHeader)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// #nosec G704 -- request is routed through the SSRF-safe egress client (internal/httpsafe): scheme allow-list, resolve-and-pin private-range deny-list, per-hop redirect re-validation
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return WrapRemoteError(0, "failed to exchange code", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(LimitErrorBody(resp.Body))
		return WrapRemoteError(resp.StatusCode, "oauth code exchange failed", fmt.Errorf("%s", body))
	}

	if err := json.NewDecoder(LimitBody(resp.Body)).Decode(out); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}
	return nil
}
