package scm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClampPagination(t *testing.T) {
	tests := []struct {
		name        string
		in          Pagination
		wantPage    int
		wantPerPage int
	}{
		{"zero value falls back to page 1, size 30", Pagination{}, 1, 30},
		{"negative page number clamps to the first page", Pagination{PageNum: -3, PageSize: 50}, 1, 50},
		{"page size above the API maximum falls back", Pagination{PageNum: 2, PageSize: 101}, 2, 30},
		{"page size at the API maximum is preserved", Pagination{PageNum: 2, PageSize: 100}, 2, 100},
		{"page size of one is preserved", Pagination{PageNum: 7, PageSize: 1}, 7, 1},
		{"negative page size falls back", Pagination{PageNum: 3, PageSize: -1}, 3, 30},
		{"defaults pass through unchanged", DefaultPagination(), 1, 30},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page, perPage := ClampPagination(tc.in)
			if page != tc.wantPage || perPage != tc.wantPerPage {
				t.Errorf("ClampPagination(%+v) = (%d, %d), want (%d, %d)",
					tc.in, page, perPage, tc.wantPage, tc.wantPerPage)
			}
		})
	}
}

func TestDoJSON_DecodesSuccessfulResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q, want the caller's header to survive untouched", got)
		}
		_, _ = w.Write([]byte(`{"name":"mod"}`))
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer tok")

	var out struct {
		Name string `json:"name"`
	}
	if err := DoJSON(req, "failed to fetch repository", ErrRepoNotFound, &out); err != nil {
		t.Fatalf("DoJSON error: %v", err)
	}
	if out.Name != "mod" {
		t.Errorf("Name = %q, want %q", out.Name, "mod")
	}
}

func TestDoJSON_StatusMapping(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		notFound   error
		wantErr    error // expected via errors.Is, when non-nil
		wantStatus int   // expected APIError.StatusCode, when wantErr is nil
	}{
		{"404 returns the caller's sentinel", http.StatusNotFound, ErrTagNotFound, ErrTagNotFound, 0},
		{"404 without a sentinel stays an APIError", http.StatusNotFound, nil, nil, http.StatusNotFound},
		{"401 keeps its status for the token-refresh path", http.StatusUnauthorized, ErrRepoNotFound, nil, http.StatusUnauthorized},
		{"403 keeps its status", http.StatusForbidden, nil, nil, http.StatusForbidden},
		{"500 keeps its status", http.StatusInternalServerError, nil, nil, http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("s3cr3t-repository-content"))
			}))
			defer srv.Close()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}

			var out map[string]any
			err = DoJSON(req, "failed to fetch repository", tc.notFound, &out)
			if err == nil {
				t.Fatal("DoJSON error = nil, want an error")
			}

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("DoJSON error = %v, want %v", err, tc.wantErr)
				}
				return
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("DoJSON error = %v (%T), want an *APIError", err, err)
			}
			if apiErr.StatusCode != tc.wantStatus {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tc.wantStatus)
			}
			// The registry surfaces these errors to API clients, so an SCM response body
			// must never be copied into them.
			if strings.Contains(err.Error(), "s3cr3t-repository-content") {
				t.Errorf("error %q leaks the SCM response body", err.Error())
			}
		})
	}
}

func TestDoJSON_TransportFailureKeepsStatusZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // nothing is listening any more

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	var out map[string]any
	err = DoJSON(req, "failed to fetch repository", ErrRepoNotFound, &out)
	if err == nil {
		t.Fatal("DoJSON error = nil, want a transport error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("DoJSON error = %v (%T), want an *APIError", err, err)
	}
	if apiErr.StatusCode != 0 {
		t.Errorf("StatusCode = %d, want 0 for a transport failure", apiErr.StatusCode)
	}
	if apiErr.Message != "failed to fetch repository" {
		t.Errorf("Message = %q, want the caller's reason", apiErr.Message)
	}
}

// TestDoJSON_RefusesGuardedTarget is the runtime half of the egress guarantee: DoJSON must
// send through the httpsafe client, which refuses link-local/metadata targets at dial time.
// A DoJSON rewritten to use a bare http.Client would reach the dial and fail differently
// (or, on a cloud host, succeed).
func TestDoJSON_RefusesGuardedTarget(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	var out map[string]any
	err = DoJSON(req, "failed to fetch repository", nil, &out)
	if err == nil {
		t.Fatal("DoJSON reached the metadata endpoint; the egress guard is not on this path")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 0 {
		t.Fatalf("DoJSON error = %v, want a transport-level *APIError from the egress guard", err)
	}
}

func TestExchangeOAuthForm_PostsFormAndDecodes(t *testing.T) {
	tests := []struct {
		name         string
		acceptHeader string
		wantAccept   string
	}{
		{"GitHub asks for a JSON token response", "application/json", "application/json"},
		{"GitLab and Entra ID send no Accept header", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotContentType, gotAccept, gotCode string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotContentType = r.Header.Get("Content-Type")
				gotAccept = r.Header.Get("Accept")
				_ = r.ParseForm()
				gotCode = r.Form.Get("code")
				_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
			}))
			defer srv.Close()

			form := url.Values{}
			form.Set("code", "auth-code")

			var result struct {
				AccessToken string `json:"access_token"`
				TokenType   string `json:"token_type"`
			}
			if err := ExchangeOAuthForm(context.Background(), srv.URL, form, tc.acceptHeader, &result); err != nil {
				t.Fatalf("ExchangeOAuthForm error: %v", err)
			}

			if gotMethod != http.MethodPost {
				t.Errorf("method = %q, want POST", gotMethod)
			}
			if gotContentType != "application/x-www-form-urlencoded" {
				t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", gotContentType)
			}
			if gotAccept != tc.wantAccept {
				t.Errorf("Accept = %q, want %q", gotAccept, tc.wantAccept)
			}
			if gotCode != "auth-code" {
				t.Errorf("code = %q, want the submitted form value", gotCode)
			}
			if result.AccessToken != "at" || result.TokenType != "bearer" {
				t.Errorf("result = %+v, want the decoded token response", result)
			}
		})
	}
}

func TestExchangeOAuthForm_NonOKCarriesStatusAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	var result struct{}
	err := ExchangeOAuthForm(context.Background(), srv.URL, url.Values{}, "", &result)
	if err == nil {
		t.Fatal("ExchangeOAuthForm error = nil, want an error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v (%T), want an *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusBadRequest)
	}
	// Unlike the repository APIs, the OAuth failure reason is what makes a misconfigured
	// app registration diagnosable, so it is deliberately carried in the error.
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("error = %q, want it to carry the provider's failure reason", err.Error())
	}
}
