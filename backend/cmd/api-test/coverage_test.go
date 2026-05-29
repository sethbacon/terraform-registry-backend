package main

import (
	"encoding/json"
	"testing"
)

func TestPathMatchesTemplate(t *testing.T) {
	cases := []struct {
		concrete string
		template string
		want     bool
	}{
		{"/api/v1/admin/mirrors", "/api/v1/admin/mirrors", true},
		{"/api/v1/admin/mirrors/abc-123", "/api/v1/admin/mirrors/{id}", true},
		{"/api/v1/admin/mirrors/{id}", "/api/v1/admin/mirrors/{id}", true}, // literal placeholder from skip lists
		{"/v1/providers/hashicorp/aws/versions", "/v1/providers/{namespace}/{type}/versions", true},
		{"/v1/providers/hashicorp/aws/1.0.0/download/linux/amd64", "/v1/providers/{namespace}/{type}/{version}/download/{os}/{arch}", true},
		// negatives
		{"/api/v1/admin/mirrors", "/api/v1/admin/mirrors/{id}", false},               // segment count
		{"/api/v1/admin/mirrors/abc", "/api/v1/admin/terraform-mirrors/{id}", false}, // literal mismatch
		{"/api/v1/admin/{id}", "/api/v1/admin/mirrors", false},                       // placeholder vs literal
		{"/v1/providers/hashicorp/aws", "/v1/providers/{namespace}/{type}/versions", false},
	}
	for _, c := range cases {
		if got := pathMatchesTemplate(c.concrete, c.template); got != c.want {
			t.Errorf("pathMatchesTemplate(%q,%q)=%v want %v", c.concrete, c.template, got, c.want)
		}
	}
}

func TestLoadSpecEndpoints(t *testing.T) {
	raw := `{
	  "paths": {
	    "/api/v1/admin/mirrors": {
	      "get": {"summary": "list"},
	      "post": {"summary": "create"},
	      "parameters": []
	    },
	    "/api/v1/admin/mirrors/{id}": {
	      "get": {}, "put": {}, "delete": {}
	    }
	  }
	}`
	var spec map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	eps := loadSpecEndpoints(spec)
	// 2 + 3 = 5 operations; the non-method "parameters" key is ignored.
	if len(eps) != 5 {
		t.Fatalf("expected 5 endpoints, got %d: %+v", len(eps), eps)
	}
	// Sorted: path then method.
	if eps[0].Template != "/api/v1/admin/mirrors" || eps[0].Method != "GET" {
		t.Fatalf("unexpected first endpoint: %+v", eps[0])
	}
}

func TestLoadSpecEndpoints_NoPaths(t *testing.T) {
	if eps := loadSpecEndpoints(map[string]interface{}{}); eps != nil {
		t.Fatalf("expected nil for spec without paths, got %+v", eps)
	}
}

func TestUncoveredEndpoints(t *testing.T) {
	spec := []endpoint{
		{Method: "GET", Template: "/api/v1/admin/mirrors"},
		{Method: "POST", Template: "/api/v1/admin/mirrors"},
		{Method: "GET", Template: "/api/v1/admin/mirrors/{id}"},
		{Method: "DELETE", Template: "/api/v1/admin/mirrors/{id}"},
		{Method: "GET", Template: "/api/v1/admin/version-approvals"},
	}
	hits := []touchedEndpoint{
		{Method: "GET", Path: "/api/v1/admin/mirrors"},
		{Method: "POST", Path: "/api/v1/admin/mirrors"},
		{Method: "GET", Path: "/api/v1/admin/mirrors/abc-123"}, // covers the {id} GET
	}

	missing := uncoveredEndpoints(spec, hits)
	// DELETE /mirrors/{id} and GET /version-approvals are uncovered.
	if len(missing) != 2 {
		t.Fatalf("expected 2 uncovered, got %d: %+v", len(missing), missing)
	}
	wantUncovered := map[string]bool{
		"DELETE /api/v1/admin/mirrors/{id}":   true,
		"GET /api/v1/admin/version-approvals": true,
	}
	for _, ep := range missing {
		if !wantUncovered[ep.Method+" "+ep.Template] {
			t.Errorf("unexpected uncovered endpoint: %s %s", ep.Method, ep.Template)
		}
	}
}

func TestMarkTouched_StripsQueryString(t *testing.T) {
	saved := touched
	t.Cleanup(func() { touched = saved })
	touched = nil

	markTouched("GET", "/api/v1/admin/version-approvals?status=pending_approval&type=provider")
	if len(touched) != 1 {
		t.Fatalf("expected 1 touched entry, got %d", len(touched))
	}
	if touched[0].Path != "/api/v1/admin/version-approvals" {
		t.Fatalf("query string not stripped: %q", touched[0].Path)
	}
	if touched[0].Method != "GET" {
		t.Fatalf("method not normalised: %q", touched[0].Method)
	}
}
