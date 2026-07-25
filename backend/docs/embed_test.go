package docs

import (
	"encoding/json"
	"testing"
)

// TestSwaggerJSONCoversNamespaceOwnershipAPI guards against issue #672's
// documentation gap recurring: the namespace-ownership endpoints
// (ListNamespaceClaimsHandler / GetNamespaceOwnershipHandler,
// internal/api/admin/organizations.go) were registered in router_routes.go
// with no Swagger annotations, so they were silently absent from the
// generated spec and therefore invisible to cmd/api-test's swagger-coverage
// report. This test fails if the annotations (or the generated spec) regress.
func TestSwaggerJSONCoversNamespaceOwnershipAPI(t *testing.T) {
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(SwaggerJSON, &spec); err != nil {
		t.Fatalf("failed to parse embedded swagger.json: %v", err)
	}

	for _, path := range []string{
		"/api/v1/admin/namespaces",
		"/api/v1/admin/namespaces/{namespace}",
	} {
		if _, ok := spec.Paths[path]; !ok {
			t.Errorf("swagger.json is missing path %q; run `swag init -g cmd/server/main.go --outputTypes json` from backend/ after adding Swagger annotations", path)
		}
	}
}
