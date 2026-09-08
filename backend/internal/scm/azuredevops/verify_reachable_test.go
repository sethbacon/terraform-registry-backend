package azuredevops

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// GUARD verify-proves-organization-not-only-credential (issue #1036).
//
// Minting an Entra token proves the app registration's client secret is
// valid; it proves nothing about Azure DevOps, which has its own permission
// model and does not honour Entra application permissions. A service
// principal can hold a perfectly good token and still be unable to reach the
// organization because nobody added it under Organization settings -> Users.
// VerifyOrganizationReachable is the one call that actually proves both.

func TestVerifyOrganizationReachable_Success(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/_apis/projects") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(struct {
			Value []adoProject `json:"value"`
		}{Value: []adoProject{{ID: "p1", Name: "project1"}}})
	})

	if err := c.VerifyOrganizationReachable(t.Context(), creds()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyOrganizationReachable_ValidTokenButOrgUnreachable(t *testing.T) {
	// The exact shape the issue describes: a valid Entra token, but the service
	// principal was never added to the organization. Azure DevOps answers with
	// its own 401/203, not an Entra error.
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "TF400813: The user is not authorized to access this resource."}`))
	})

	err := c.VerifyOrganizationReachable(t.Context(), creds())
	if err == nil {
		t.Fatal("expected an error: a valid credential does not by itself grant Azure DevOps access")
	}
	if !strings.Contains(err.Error(), c.organization) {
		t.Errorf("error should name the organization that was unreachable, got: %v", err)
	}
}

func TestVerifyOrganizationReachable_NoOrganizationConfigured(t *testing.T) {
	// A pre-#1036 row whose base_url predates the CreateProvider/UpdateProvider
	// guard. Must name the real problem, not attempt a request that would
	// produce a double-slash 404 indistinguishable from an org-membership
	// failure.
	c, err := NewAzureDevOpsConnector(&scm.ConnectorSettings{})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	if err := c.VerifyOrganizationReachable(t.Context(), creds()); err == nil {
		t.Fatal("expected an error when no organization is configured")
	} else if !strings.Contains(err.Error(), "no organization configured") {
		t.Errorf("error should name the real problem, got: %v", err)
	}
}

// GUARD organization-parser-is-the-single-source-of-truth (issue #1036).
//
// ParseOrganization is called from both the constructor and
// RequireOrganization (internal/api/admin/scm_providers.go, through this
// package). One parser means the validator that runs at create/update time
// and the connector that runs at request time can never disagree about which
// URLs are valid.

func TestParseOrganization(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		org        string
		host       string
		wantErr    bool
		errNeedles []string
	}{
		{"empty is not an error, it means unconfigured", "", "", "", false, nil},
		{"org in the path", "https://dev.azure.com/myorg", "myorg", "https://dev.azure.com", false, nil},
		{"self-hosted host, org in the path", "https://ado.corp.example.com/myorg", "myorg", "https://ado.corp.example.com", false, nil},
		{"trailing slash", "https://dev.azure.com/myorg/", "myorg", "https://dev.azure.com", false, nil},
		{"a second path segment is ignored, not required", "https://dev.azure.com/myorg/extra", "myorg", "https://dev.azure.com", false, nil},
		{"bare host, no organization", "https://dev.azure.com", "", "", true, []string{"no organization", "dev.azure.com/<org>"}},
		{"bare host with trailing slash", "https://dev.azure.com/", "", "", true, []string{"no organization"}},
		{"not a URL at all", "://not a url", "", "", true, []string{"not a valid URL"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			org, host, err := ParseOrganization(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got org=%q host=%q", tc.in, org, host)
				}
				for _, needle := range tc.errNeedles {
					if !strings.Contains(err.Error(), needle) {
						t.Errorf("error %q missing expected text %q", err.Error(), needle)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if org != tc.org {
				t.Errorf("org = %q, want %q", org, tc.org)
			}
			if host != tc.host {
				t.Errorf("host = %q, want %q", host, tc.host)
			}
		})
	}
}

func TestRequireOrganization(t *testing.T) {
	ok := "https://dev.azure.com/myorg"
	bad := "https://dev.azure.com"
	empty := ""
	cases := []struct {
		name    string
		in      *string
		wantErr bool
	}{
		{"nil is required", nil, true},
		{"empty string is required", &empty, true},
		{"a URL with no organization is required", &bad, true},
		{"a valid org URL passes", &ok, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RequireOrganization(tc.in)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
