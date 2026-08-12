// connector_status_test.go covers the response-status handling every Azure DevOps listing
// call has to share: a non-200 must become an error (never a silently short result), and the
// HTTP 203 sign-in page ADO returns instead of 401 for an expired token must be reported as
// 401 so the callers' token-refresh-and-retry path fires.
package azuredevops

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// adoSignInPage is what Azure DevOps actually returns when the bearer token has expired:
// HTTP 203 Non-Authoritative Information carrying an HTML sign-in page instead of a 401.
const adoSignInPage = `<!DOCTYPE html><html><head><title>Sign In</title></head><body>Sign in to Azure DevOps</body></html>`

// listingCall is one Azure DevOps listing method, reduced to a no-result call so the whole
// class can be driven from one table. Every entry must surface an upstream non-200 as an
// error rather than an empty or short success.
type listingCall struct {
	name string
	call func(c *AzureDevOpsConnector) error
}

func listingCalls() []listingCall {
	ctx := context.Background()
	return []listingCall{
		{"FetchRepositories", func(c *AzureDevOpsConnector) error {
			_, err := c.FetchRepositories(ctx, creds(), scm.DefaultPagination())
			return err
		}},
		{"SearchRepositories", func(c *AzureDevOpsConnector) error {
			_, err := c.SearchRepositories(ctx, creds(), "terraform", scm.DefaultPagination())
			return err
		}},
		{"FetchRepository", func(c *AzureDevOpsConnector) error {
			_, err := c.FetchRepository(ctx, creds(), "proj", "repo")
			return err
		}},
		{"FetchBranches", func(c *AzureDevOpsConnector) error {
			_, err := c.FetchBranches(ctx, creds(), "proj", "repo", scm.DefaultPagination())
			return err
		}},
		{"FetchTags", func(c *AzureDevOpsConnector) error {
			_, err := c.FetchTags(ctx, creds(), "proj", "repo", scm.DefaultPagination())
			return err
		}},
		{"FetchCommit", func(c *AzureDevOpsConnector) error {
			_, err := c.FetchCommit(ctx, creds(), "proj", "repo", "deadbeef")
			return err
		}},
	}
}

// TestListingCalls_ExpiredTokenReportedAs401 pins the 203→401 normalisation across the whole
// listing surface. The assertion is on the *scm.APIError status code specifically — the
// handlers in internal/api/admin/scm_oauth.go decide whether to refresh the OAuth token by
// comparing that code, so "some error was returned" is not enough to keep them working.
func TestListingCalls_ExpiredTokenReportedAs401(t *testing.T) {
	for _, lc := range listingCalls() {
		t.Run(lc.name, func(t *testing.T) {
			_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusNonAuthoritativeInfo)
				_, _ = w.Write([]byte(adoSignInPage))
			})

			err := lc.call(c)
			if err == nil {
				t.Fatalf("%s returned nil error for an HTTP 203 sign-in page", lc.name)
			}
			var apiErr *scm.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("%s error %v (%T) is not a *scm.APIError; callers cannot detect the expired token",
					lc.name, err, err)
			}
			if apiErr.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s StatusCode = %d, want %d (ADO's 203 sign-in page must normalise to 401)",
					lc.name, apiErr.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

// TestListingCalls_NonOKStatusIsAnError covers the rest of the status class: any non-200 has
// to reach the caller as an error carrying the upstream status, not as an empty success.
func TestListingCalls_NonOKStatusIsAnError(t *testing.T) {
	statuses := []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusInternalServerError,
		http.StatusBadGateway,
	}

	for _, lc := range listingCalls() {
		for _, status := range statuses {
			t.Run(lc.name+"/"+http.StatusText(status), func(t *testing.T) {
				_, c := newTestConnector(t, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"message":"upstream failure"}`))
				})

				err := lc.call(c)
				if err == nil {
					t.Fatalf("%s returned nil error for upstream HTTP %d", lc.name, status)
				}
				var apiErr *scm.APIError
				if !errors.As(err, &apiErr) {
					t.Fatalf("%s error %v (%T) is not a *scm.APIError", lc.name, err, err)
				}
				if apiErr.StatusCode != status {
					t.Errorf("%s StatusCode = %d, want %d", lc.name, apiErr.StatusCode, status)
				}
			})
		}
	}
}

// TestFetchRepositories_PerProjectFailureIsNotASilentShortList is the reported defect: the
// projects call succeeds, then one project's repository listing fails. Returning the repos
// gathered so far looks like a successful result to every caller, so a browsing user silently
// sees a subset of their repositories. The call must fail instead.
func TestFetchRepositories_PerProjectFailureIsNotASilentShortList(t *testing.T) {
	tests := []struct {
		name         string
		writeFailure func(w http.ResponseWriter)
	}{
		{"expired token sign-in page", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			_, _ = w.Write([]byte(adoSignInPage))
		}},
		{"server error", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"undecodable body", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"value": not-json`))
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Two projects: the first lists one repository fine, the second fails.
			var repoCalls int
			_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
				if !isRepoListRequest(r) {
					_ = json.NewEncoder(w).Encode(struct {
						Value []adoProject `json:"value"`
					}{Value: []adoProject{{ID: "p1", Name: "project1"}, {ID: "p2", Name: "project2"}}})
					return
				}
				repoCalls++
				if repoCalls == 1 {
					_ = json.NewEncoder(w).Encode(struct {
						Value []adoRepo `json:"value"`
					}{Value: []adoRepo{{ID: "r1", Name: "terraform-module-network"}}})
					return
				}
				tc.writeFailure(w)
			})

			result, err := c.FetchRepositories(context.Background(), creds(), scm.DefaultPagination())
			if err == nil {
				t.Fatalf("FetchRepositories returned a short list of %d repo(s) with nil error; "+
					"a truncated listing must be reported as a failure", len(result.Repos))
			}
			if result != nil {
				t.Errorf("FetchRepositories returned %+v alongside an error; callers must not see partial results", result)
			}
		})
	}
}

// TestFetchRepositories_ErrorsCarryNoUpstreamBody keeps SCM response content out of the error
// text: these errors are formatted straight into the JSON body of the repository-listing
// endpoint, so an HTML sign-in page or an upstream diagnostic must not ride along.
func TestFetchRepositories_ErrorsCarryNoUpstreamBody(t *testing.T) {
	const marker = "Sign in to Azure DevOps"

	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if !isRepoListRequest(r) {
			_ = json.NewEncoder(w).Encode(struct {
				Value []adoProject `json:"value"`
			}{Value: []adoProject{{ID: "p1", Name: "project1"}}})
			return
		}
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		_, _ = w.Write([]byte(adoSignInPage))
	})

	_, err := c.FetchRepositories(context.Background(), creds(), scm.DefaultPagination())
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("error text %q embeds the upstream response body", err.Error())
	}
}

// TestFetchRepositories_SucceedsAcrossProjects is the happy path the failure cases above must
// not have broken: every project's repositories are collected and attributed to its project.
func TestFetchRepositories_SucceedsAcrossProjects(t *testing.T) {
	_, c := newTestConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if !isRepoListRequest(r) {
			_ = json.NewEncoder(w).Encode(struct {
				Value []adoProject `json:"value"`
			}{Value: []adoProject{{ID: "p1", Name: "project1"}, {ID: "p2", Name: "project2"}}})
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			Value []adoRepo `json:"value"`
		}{Value: []adoRepo{{ID: "r1", Name: "mod"}}})
	})

	result, err := c.FetchRepositories(context.Background(), creds(), scm.DefaultPagination())
	if err != nil {
		t.Fatalf("FetchRepositories error: %v", err)
	}
	if len(result.Repos) != 2 {
		t.Fatalf("Repos len = %d, want 2 (one per project)", len(result.Repos))
	}
	if result.Repos[0].FullName != "project1/mod" || result.Repos[1].FullName != "project2/mod" {
		t.Errorf("unexpected repo names: %q, %q", result.Repos[0].FullName, result.Repos[1].FullName)
	}
}

// isRepoListRequest distinguishes the per-project repository listing from the projects
// listing that FetchRepositories issues first.
func isRepoListRequest(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/_apis/git/repositories")
}
