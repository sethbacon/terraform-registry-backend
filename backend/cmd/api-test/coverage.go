// coverage.go adds spec-coverage reporting to the integration runner. Every
// endpoint the runner touches (via record/skipTest) is recorded; at the end we
// fetch the live OpenAPI spec, match each spec path+method against the touched
// set, and report the endpoints that have no integration coverage.
//
// This keeps the runner honest as the API grows: when a new endpoint ships, it
// shows up as uncovered here instead of silently going untested. Matching is
// template-aware so a touched concrete path like /admin/mirrors/<uuid> (or the
// literal /admin/mirrors/{id} used in skip lists) counts as covering the spec
// template /admin/mirrors/{id}.
package main

import (
	"fmt"
	"sort"
	"strings"
)

// httpMethods is the set of keys under a spec path object that denote operations.
var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true,
	"delete": true, "head": true, "options": true,
}

// endpoint is a method+path-template pair from the OpenAPI spec.
type endpoint struct {
	Method   string // upper-case (GET, POST, …)
	Template string // e.g. /api/v1/admin/mirrors/{id}
}

// touchedEndpoint is a method+concrete-path the runner exercised.
type touchedEndpoint struct {
	Method string
	Path   string // concrete path as called (query string already stripped)
}

// touched accumulates every endpoint the runner hits. Populated from record()
// and skipTest() so both executed and intentionally-skipped endpoints count as
// "covered" — a skip still means the runner knows the endpoint exists.
var touched []touchedEndpoint

// markTouched records that the runner exercised method+path. The query string
// is stripped so /x?status=y collapses to /x.
func markTouched(method, path string) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	touched = append(touched, touchedEndpoint{Method: strings.ToUpper(method), Path: path})
}

// loadSpecEndpoints parses the "paths" object of an OpenAPI 2.0/3.0 spec (both
// share the path→method→operation shape) into a flat, sorted endpoint list.
func loadSpecEndpoints(spec map[string]interface{}) []endpoint {
	pathsRaw, ok := spec["paths"].(map[string]interface{})
	if !ok {
		return nil
	}
	var out []endpoint
	for path, v := range pathsRaw {
		ops, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		for method := range ops {
			if httpMethods[strings.ToLower(method)] {
				out = append(out, endpoint{Method: strings.ToUpper(method), Template: path})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Template != out[j].Template {
			return out[i].Template < out[j].Template
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// pathMatchesTemplate reports whether a concrete path matches a spec template.
// Segments must align one-to-one; a template parameter segment ({id}) matches
// any non-empty concrete segment, and a concrete segment that is itself a
// placeholder ({id}) matches a template parameter segment.
func pathMatchesTemplate(concrete, template string) bool {
	cs := strings.Split(strings.Trim(concrete, "/"), "/")
	ts := strings.Split(strings.Trim(template, "/"), "/")
	if len(cs) != len(ts) {
		return false
	}
	for i := range ts {
		tParam := strings.HasPrefix(ts[i], "{") && strings.HasSuffix(ts[i], "}")
		cParam := strings.HasPrefix(cs[i], "{") && strings.HasSuffix(cs[i], "}")
		if tParam {
			if cs[i] == "" {
				return false
			}
			continue // any concrete value (or placeholder) covers a param segment
		}
		if cParam {
			// A literal-placeholder concrete segment can only match a param
			// template segment, which is handled above; against a literal
			// template segment it does not match.
			return false
		}
		if cs[i] != ts[i] {
			return false
		}
	}
	return true
}

// reportCoverage fetches the live OpenAPI spec, diffs it against the touched
// endpoints, prints a coverage summary, and returns the number of uncovered
// endpoints. A spec that cannot be loaded is reported but not treated as a
// failure (returns 0) so the coverage check never masks real test results.
func reportCoverage() int {
	r := doJSON("GET", "/swagger.json", nil, false)
	fmt.Println("\n--- API Coverage ---")
	if r.Code != 200 || r.Object == nil {
		fmt.Println("  spec unavailable (GET /swagger.json did not return a JSON object); skipping coverage check")
		return 0
	}

	spec := loadSpecEndpoints(r.Object)
	if len(spec) == 0 {
		fmt.Println("  no paths found in spec; skipping coverage check")
		return 0
	}

	missing := uncoveredEndpoints(spec, touched)
	covered := len(spec) - len(missing)
	fmt.Printf("  %d/%d spec endpoints exercised (%.0f%%)\n",
		covered, len(spec), float64(covered)/float64(len(spec))*100)

	if len(missing) > 0 {
		fmt.Printf("  %d endpoint(s) with no integration coverage:\n", len(missing))
		for _, ep := range missing {
			fmt.Printf("    %-7s %s\n", ep.Method, ep.Template)
		}
	}
	return len(missing)
}

// uncoveredEndpoints returns spec endpoints with no matching touched endpoint,
// sorted for stable output.
func uncoveredEndpoints(spec []endpoint, hits []touchedEndpoint) []endpoint {
	var missing []endpoint
	for _, ep := range spec {
		covered := false
		for _, h := range hits {
			if h.Method == ep.Method && pathMatchesTemplate(h.Path, ep.Template) {
				covered = true
				break
			}
		}
		if !covered {
			missing = append(missing, ep)
		}
	}
	return missing
}
