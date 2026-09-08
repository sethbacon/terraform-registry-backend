package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// GUARD verify-checks-organization-reachability (issue #1036).
//
// Minting an Entra token proves the app registration's client secret is valid.
// It proves nothing about Azure DevOps, which has its own permission model and
// does not honour Entra application permissions: a service principal can hold a
// perfectly good token and still be unable to reach the organization because
// nobody added it under Organization settings -> Users.
//
// Before this fix VerifyProvider returned {"ok": true} the moment the mint
// succeeded, so an operator reading "Connection OK" learned nothing about
// whether the provider could fetch a single repository.
//
// These drive the real handler, the real connector and the real parser. Only
// two things are substituted: the minter (so no live Entra call is needed --
// what is under test is what happens AFTER a successful mint) and the
// connector's base URL (so the ADO call lands on a local server).

// stubMinter always mints successfully.
type stubMinter struct{}

func (stubMinter) MintProviderToken(_ context.Context, _ *scm.SCMProvider) (*scm.OAuthToken, error) {
	return &scm.OAuthToken{AccessToken: "stub-token"}, nil
}

// allowLoopbackEgress points the shared connector client at a permissive
// client for one test and restores it afterwards. scm.HTTPClient is
// process-global and ConfigureEgress installs a strict guard, so without this
// a request to an httptest server is refused at dial time -- and a test that
// "passes" on that refusal is asserting the guard, not the behaviour under
// test. httpclient.go's own doc names this as the intended pattern.
func allowLoopbackEgress(t *testing.T) {
	t.Helper()
	prev := scm.HTTPClient
	scm.HTTPClient = httpsafe.NewClient(30*time.Second, httpsafe.MustGuard("127.0.0.1", "::1"))
	t.Cleanup(func() { scm.HTTPClient = prev })
}

// newVerifyRouter wires VerifyProvider with a minter that always succeeds.
func newVerifyRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	orgRepo := repositories.NewOrganizationRepository(db)
	h := NewSCMProviderHandlers(&config.Config{}, scmRepo, orgRepo, testTokenCipher(t)).
		WithMinter(stubMinter{})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Set("user_id", "test-admin")
	})
	r.POST("/scm-providers/:id/verify", h.VerifyProvider)
	return mock, r
}

// entraAppADORow is an azuredevops provider in entra_app mode. base_url points
// at the caller's test server with the organization segment intact, which is
// exactly how the handler reaches Azure DevOps in production -- it reads
// base_url from this row and hands it to the connector. SELECT * plus sqlx
// struct scanning means the fixture chooses its own columns, so auth_mode is
// set here where the shared fixture cannot.
func entraAppADORow(baseURL string) *sqlmock.Rows {
	cols := append(append([]string{}, scmProvCols...), "auth_mode")
	return sqlmock.NewRows(cols).AddRow(
		knownUUID, "00000000-0000-0000-0000-000000000000", "azuredevops", "ado-app",
		baseURL, "tenant-1", "client-1",
		"encrypted-secret", "webhook-secret",
		true, time.Now(), time.Now(),
		string(scm.AuthModeEntraApp),
	)
}

func TestSCMVerify_AzureDevOps_ReachableOrganizationIsOK(t *testing.T) {
	ado := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/_apis/projects") {
			t.Errorf("unexpected ADO path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"p1","name":"project1"}]}`))
	}))
	defer ado.Close()
	allowLoopbackEgress(t)

	mock, r := newVerifyRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE id").WillReturnRows(entraAppADORow(ado.URL + "/acme-org"))
	mock.ExpectExec("DELETE FROM scm_provider_tokens").WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers/"+knownUUID+"/verify", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Errorf("body = %s, want ok:true", w.Body.String())
	}
}

func TestSCMVerify_AzureDevOps_ValidTokenButUnreachableOrgIsNotOK(t *testing.T) {
	// The defect this issue reports: the mint succeeds, so the old code said
	// {"ok": true}. Azure DevOps itself refuses, because the service principal
	// was never added to the organization.
	ado := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"TF400813: not authorized"}`))
	}))
	defer ado.Close()
	allowLoopbackEgress(t)

	mock, r := newVerifyRouter(t)
	mock.ExpectQuery("SELECT.*FROM scm_providers.*WHERE id").WillReturnRows(entraAppADORow(ado.URL + "/acme-org"))
	mock.ExpectExec("DELETE FROM scm_provider_tokens").WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/scm-providers/"+knownUUID+"/verify", nil))

	if w.Code == http.StatusOK {
		t.Fatalf("status = 200 for an unreachable organization: a valid Entra token does not "+
			"by itself grant Azure DevOps access. body=%s", w.Body.String())
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
	if !strings.Contains(w.Body.String(), "acme-org") {
		t.Errorf("body should name the unreachable organization: %s", w.Body.String())
	}
}

// GUARD base-url-carries-the-organization (issue #1036).
//
// base_url is the ONLY source of the Azure DevOps organization: the connector
// parses it from the first path segment, and every endpoint template
// interpolates it. A provider saved without one used to pass /verify and then
// emit https://dev.azure.com//_apis/... on every real call. These cover create
// (both auth modes, since the connector parses the same field either way).

func TestSCMCreate_AzureDevOps_RejectsMissingBaseURL(t *testing.T) {
	for _, authMode := range []string{"entra_app", "oauth_user"} {
		t.Run(authMode, func(t *testing.T) {
			mock, r := newSCMProviderAppRouter(t)
			expectActingOrgAndNoDuplicate(mock)

			body := map[string]interface{}{
				"provider_type": "azuredevops",
				"name":          "ado-no-base-url",
				"auth_mode":     authMode,
				"tenant_id":     "tenant-1",
				"client_id":     "client-1",
				"client_secret": "super-secret",
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers", jsonBody(body)), knownUUID))

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 -- without base_url there is no organization "+
					"and every ADO call emits a double-slash URL: body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "organization") {
				t.Errorf("error should explain that the organization is what is missing: %s", w.Body.String())
			}
		})
	}
}

func TestSCMCreate_AzureDevOps_RejectsBaseURLWithNoOrganizationSegment(t *testing.T) {
	mock, r := newSCMProviderAppRouter(t)
	expectActingOrgAndNoDuplicate(mock)

	// A bare host: parses fine as a URL, but carries no organization. This is
	// the shape that silently produced organization="" before #1036.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "azuredevops",
			"name":          "ado-bare-host",
			"auth_mode":     "entra_app",
			"tenant_id":     "tenant-1",
			"client_id":     "client-1",
			"client_secret": "super-secret",
			"base_url":      "https://dev.azure.com",
		})), knownUUID))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a base_url with no organization segment: body=%s",
			w.Code, w.Body.String())
	}
}

func TestSCMCreate_NonAzureDevOps_StillDoesNotRequireBaseURL(t *testing.T) {
	// The requirement is Azure DevOps-specific. GitHub has no organization in
	// its base URL and must not be caught by it.
	mock, r := newSCMProviderAppRouter(t)
	expectActingOrgAndNoDuplicate(mock)
	mock.ExpectExec("INSERT INTO scm_providers").WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, withActingOrg(httptest.NewRequest("POST", "/scm-providers",
		jsonBody(map[string]interface{}{
			"provider_type": "github",
			"name":          "gh",
			"auth_mode":     "oauth_user",
			"client_id":     "client-1",
			"client_secret": "super-secret",
		})), knownUUID))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 -- the base_url requirement is Azure DevOps-only: body=%s",
			w.Code, w.Body.String())
	}
}
