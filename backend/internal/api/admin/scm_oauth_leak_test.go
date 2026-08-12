// scm_oauth_leak_test.go asserts that an SCM provider's raw response detail never reaches an
// API client through an OAuth handler's JSON body. The connector errors these handlers format
// can carry the provider's token-endpoint response (see scm.APIError.RemoteBody); the OAuth
// callback that used to echo one verbatim is routed unauthenticated.
package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// upstreamMarker stands in for whatever an SCM/OAuth provider puts in a failure body:
// internal hostnames, app-registration identifiers, stack detail.
const upstreamMarker = "upstream-internal-detail-must-not-leak"

// leakyConnector is an scm.Connector whose token operations fail the way a real one does
// when the provider rejects the exchange — with an *scm.APIError carrying the provider's
// response body. It is registered against the GitLab kind, which is a valid provider type
// whose real connector is not linked into this test binary (only github is imported here),
// so nothing else in the package is affected.
type leakyConnector struct{ scm.Connector }

func leakyAPIError(message string) error {
	err := scm.WrapRemoteError(http.StatusBadRequest, message, nil)
	err.RemoteBody = `{"error":"invalid_client","error_description":"` + upstreamMarker + `"}`
	return err
}

func (leakyConnector) Platform() scm.ProviderKind { return scm.ProviderGitLab }

func (leakyConnector) RenewToken(context.Context, string) (*scm.AccessToken, error) {
	return nil, leakyAPIError("failed to refresh token")
}

func (leakyConnector) CompleteAuthorization(context.Context, string) (*scm.AccessToken, error) {
	return nil, leakyAPIError("oauth code exchange failed")
}

func registerLeakyConnector(t *testing.T) {
	t.Helper()
	scm.RegisterConnector(scm.ProviderGitLab, func(*scm.ConnectorSettings) (scm.Connector, error) {
		return leakyConnector{}, nil
	})
}

// TestRefreshToken_DoesNotEchoUpstreamBody drives POST /oauth/refresh to the connector call
// and asserts the response body carries none of the provider's detail.
func TestRefreshToken_DoesNotEchoUpstreamBody(t *testing.T) {
	registerLeakyConnector(t)

	tc := oauthCipher(t)
	mock, r := newSCMOAuthRouterWithCipher(t, oauthUserUUID, tc)

	encRefresh, err := tc.SealWithContext("stored-refresh-token",
		scm.UserRefreshTokenContext(mustParseUUID(oauthUserUUID), mustParseUUID(oauthProviderID)))
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}

	// GetUserToken → an OAuth token record with a refresh token.
	mock.ExpectQuery("SELECT.*FROM scm_oauth_tokens").
		WillReturnRows(sqlmock.NewRows(scmOAuthTokenCols).AddRow(
			"00000000-0000-0000-0000-000000000010",
			oauthUserUUID,
			oauthProviderID,
			"access-token-encrypted",
			encRefresh,
			"bearer",
			time.Now().Add(-time.Hour),
			nil,
			time.Now().Add(-24*time.Hour),
			time.Now().Add(-24*time.Hour),
		))

	// GetProvider → a GitLab provider, which builds the leaky connector above.
	mock.ExpectQuery("SELECT.*FROM scm_providers WHERE id").
		WillReturnRows(oauthSCMProviderRowEncrypted(t, tc, "gitlab"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/scm-providers/"+oauthProviderID+"/oauth/refresh", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (the refresh failed): body=%s", w.Code, w.Body.String())
	}
	// Pin the exact branch: every earlier failure in this handler (decrypt, connector
	// build) also answers 500 with a non-empty error, so without this the test would pass
	// having never reached the connector call it exists to cover.
	assertNoUpstreamDetail(t, w.Body.String(), "token refresh failed")
}

// assertNoUpstreamDetail fails when a response body carries the provider's raw detail, and
// requires the exact generic message the handler is supposed to substitute — which both
// proves the request reached the branch under test and rejects an empty body that would
// otherwise "pass" this guard while telling the caller nothing.
func assertNoUpstreamDetail(t *testing.T, body, wantMessage string) {
	t.Helper()

	if strings.Contains(body, upstreamMarker) {
		t.Errorf("response body %q echoes the upstream provider's response detail", body)
	}
	if strings.Contains(body, "invalid_client") {
		t.Errorf("response body %q echoes the upstream provider's error code", body)
	}

	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("response body %q is not JSON: %v", body, err)
	}
	if payload.Error != wantMessage {
		t.Fatalf("error = %q, want %q — the request did not reach the branch under test", payload.Error, wantMessage)
	}
}
