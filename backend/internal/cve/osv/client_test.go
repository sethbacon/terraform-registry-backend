package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NormalizeSeverity
// ---------------------------------------------------------------------------

func TestNormalizeSeverity_Critical(t *testing.T) {
	adv := Advisory{Severity: []Severity{{Type: "CVSS_V3", Score: "9.8"}}}
	if got := NormalizeSeverity(adv); got != "critical" {
		t.Errorf("expected critical, got %q", got)
	}
}

func TestNormalizeSeverity_High(t *testing.T) {
	adv := Advisory{Severity: []Severity{{Type: "CVSS_V3", Score: "7.5"}}}
	if got := NormalizeSeverity(adv); got != "high" {
		t.Errorf("expected high, got %q", got)
	}
}

func TestNormalizeSeverity_Medium(t *testing.T) {
	adv := Advisory{Severity: []Severity{{Type: "CVSS_V3", Score: "5.0"}}}
	if got := NormalizeSeverity(adv); got != "medium" {
		t.Errorf("expected medium, got %q", got)
	}
}

func TestNormalizeSeverity_Low(t *testing.T) {
	adv := Advisory{Severity: []Severity{{Type: "CVSS_V3", Score: "2.0"}}}
	if got := NormalizeSeverity(adv); got != "low" {
		t.Errorf("expected low, got %q", got)
	}
}

func TestNormalizeSeverity_Unknown_NoSeverity(t *testing.T) {
	adv := Advisory{}
	if got := NormalizeSeverity(adv); got != "unknown" {
		t.Errorf("expected unknown, got %q", got)
	}
}

func TestNormalizeSeverity_Unknown_NonCVSSV3(t *testing.T) {
	adv := Advisory{Severity: []Severity{{Type: "CVSS_V2", Score: "9.0"}}}
	if got := NormalizeSeverity(adv); got != "unknown" {
		t.Errorf("expected unknown for CVSS_V2, got %q", got)
	}
}

func TestNormalizeSeverity_Unknown_ZeroScore(t *testing.T) {
	adv := Advisory{Severity: []Severity{{Type: "CVSS_V3", Score: "0.0"}}}
	if got := NormalizeSeverity(adv); got != "unknown" {
		t.Errorf("expected unknown for 0.0 score, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// ReferenceURLs
// ---------------------------------------------------------------------------

func TestReferenceURLs_Multiple(t *testing.T) {
	adv := Advisory{
		References: []Ref{
			{Type: "WEB", URL: "https://example.com/1"},
			{Type: "FIX", URL: "https://example.com/2"},
		},
	}
	urls := ReferenceURLs(adv)
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d", len(urls))
	}
	if urls[0] != "https://example.com/1" || urls[1] != "https://example.com/2" {
		t.Errorf("unexpected URLs: %v", urls)
	}
}

func TestReferenceURLs_Empty(t *testing.T) {
	adv := Advisory{}
	urls := ReferenceURLs(adv)
	if len(urls) != 0 {
		t.Errorf("expected 0 URLs, got %d", len(urls))
	}
}

func TestReferenceURLs_SkipsEmptyURL(t *testing.T) {
	adv := Advisory{
		References: []Ref{
			{Type: "WEB", URL: ""},
			{Type: "WEB", URL: "https://example.com/1"},
		},
	}
	urls := ReferenceURLs(adv)
	if len(urls) != 1 {
		t.Errorf("expected 1 URL (empty filtered), got %d", len(urls))
	}
}

// ---------------------------------------------------------------------------
// CanonicalID
// ---------------------------------------------------------------------------

func TestCanonicalID_PrefersCVEAlias(t *testing.T) {
	adv := Advisory{ID: "GHSA-xxxx", Aliases: []string{"GHSA-yyyy", "CVE-2024-1234"}}
	if got := CanonicalID(adv); got != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %q", got)
	}
}

func TestCanonicalID_FallsBackToOSVID(t *testing.T) {
	adv := Advisory{ID: "GHSA-xxxx", Aliases: []string{"GO-2024-0001"}}
	if got := CanonicalID(adv); got != "GHSA-xxxx" {
		t.Errorf("expected GHSA-xxxx, got %q", got)
	}
}

func TestCanonicalID_NoAliases(t *testing.T) {
	adv := Advisory{ID: "GHSA-zzzz"}
	if got := CanonicalID(adv); got != "GHSA-zzzz" {
		t.Errorf("expected GHSA-zzzz, got %q", got)
	}
}

func TestCanonicalID_ShortAlias_NotCVE(t *testing.T) {
	// Alias shorter than 4 chars should not panic and should fall back to ID.
	adv := Advisory{ID: "GHSA-test", Aliases: []string{"CVE"}} // len=3, no dash at [3]
	if got := CanonicalID(adv); got != "GHSA-test" {
		t.Errorf("expected GHSA-test, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// QueryBatch — HTTP test server
// ---------------------------------------------------------------------------

func newTestServer(t *testing.T, handler http.Handler) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, NewClient(srv.URL)
}

func TestQueryBatch_Success(t *testing.T) {
	published := time.Now().Add(-24 * time.Hour)
	resp := BatchResponse{
		Results: []QueryResult{
			{Vulns: []Advisory{{ID: "GHSA-0001", Summary: "test vuln", Published: &published}}},
			{Vulns: nil},
		},
	}
	srv, client := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	_ = srv

	queries := []Query{
		{Package: Package{Ecosystem: "Go", Name: "github.com/example/foo"}, Version: "1.0.0"},
		{Package: Package{Ecosystem: "Go", Name: "github.com/example/bar"}, Version: "2.0.0"},
	}
	results, err := client.QueryBatch(context.Background(), queries)
	if err != nil {
		t.Fatalf("QueryBatch error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if len(results[0].Vulns) != 1 || results[0].Vulns[0].ID != "GHSA-0001" {
		t.Errorf("unexpected first result: %+v", results[0])
	}
}

func TestQueryBatch_Empty(t *testing.T) {
	client := NewClient("")
	results, err := client.QueryBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error for empty query: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results for empty input, got %v", results)
	}
}

func TestQueryBatch_FallbackToSingle(t *testing.T) {
	callCount := 0
	srv, client := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path == "/v1/querybatch" {
			// Return HTTP 500 to trigger fallback
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Single query fallback
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(QueryResult{Vulns: []Advisory{{ID: "FALLBACK-1"}}})
	}))
	_ = srv

	queries := []Query{
		{Package: Package{Ecosystem: "Go", Name: "foo"}, Version: "1.0.0"},
	}
	results, err := client.QueryBatch(context.Background(), queries)
	if err != nil {
		t.Fatalf("QueryBatch with fallback error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if len(results[0].Vulns) != 1 || results[0].Vulns[0].ID != "FALLBACK-1" {
		t.Errorf("unexpected fallback result: %+v", results[0])
	}
}

func TestQuerySingle_Success(t *testing.T) {
	srv, client := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(QueryResult{Vulns: []Advisory{{ID: "CVE-2024-9999"}}})
	}))
	_ = srv

	vulns, err := client.QuerySingle(context.Background(), Query{
		Package: Package{Ecosystem: "Go", Name: "example"}, Version: "1.0.0",
	})
	if err != nil {
		t.Fatalf("QuerySingle error: %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "CVE-2024-9999" {
		t.Errorf("unexpected vulns: %v", vulns)
	}
}

func TestQuerySingle_HTTPError(t *testing.T) {
	srv, client := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	_ = srv

	_, err := client.QuerySingle(context.Background(), Query{
		Package: Package{Ecosystem: "Go", Name: "example"}, Version: "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error for HTTP 400, got nil")
	}
}

func TestNormalizeSeverity_CVSSVector_NotParseableAsFloat(t *testing.T) {
	// A full CVSS v3 vector string can't be parsed as a plain float; cvssV3BaseScore returns 0 → unknown
	adv := Advisory{Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}}
	if got := NormalizeSeverity(adv); got != "unknown" {
		t.Errorf("expected unknown for full CVSS vector, got %q", got)
	}
}
