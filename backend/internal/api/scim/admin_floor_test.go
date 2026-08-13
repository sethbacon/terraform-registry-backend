package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Issue #766 on the SCIM deprovision paths.
//
// SCIM is the offboarding channel with no human in the loop: it fires when HR
// disables an account, and it strips the target's memberships in every
// organization the calling credential reaches. Nothing in this package asked
// whether one of those was the deployment's last administrator.
//
// Two things are asserted: the refusal happens, and it REACHES THE CALLER. The
// second is not a formality — the two PATCH forms used to log a failed
// deprovision and return from applyReplaceOp, after which PatchUser carried on
// and answered 200 with the user still fully provisioned. An IdP feed reading
// that response has no way to learn the deactivation did not happen.

// flooredSCIMRouter mounts the four deactivation routes with a real
// adminfloor.Guard over two mocked connections, behind a PLATFORM-ADMIN
// principal so the tenant scope resolves platform-wide and the floor, rather
// than the tenant predicate, is what refuses.
func flooredSCIMRouter(t *testing.T) (*gin.Engine, sqlmock.Sqlmock, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	idb, identity, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (identity): %v", err)
	}
	t.Cleanup(func() { _ = idb.Close() })
	rdb, registry, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (registry): %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	h := NewHandlers(&config.Config{}, idb, WithAdminFloor(adminfloor.New(rdb, idb)))
	identity.MatchExpectationsInOrder(false)
	registry.MatchExpectationsInOrder(false)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin), string(auth.ScopeSCIMProvision)})
		c.Set("user_id", "scim-caller")
	})
	r.PUT("/scim/v2/Users/:id", h.PutUser())
	r.PATCH("/scim/v2/Users/:id", h.PatchUser())
	r.DELETE("/scim/v2/Users/:id", h.DeleteUser())
	return r, identity, registry
}

const floorTargetID = "dddddddd-0000-0000-0000-000000000001"

// deprovisionRequests are the four entry points, all of which funnel through
// deprovisionUser. Testing one would leave three unproven, and the pathless
// PATCH form has historically been the one that got missed (#719).
func deprovisionRequests() []struct {
	name string
	req  func() *http.Request
} {
	return []struct {
		name string
		req  func() *http.Request
	}{
		{"DELETE /Users/:id", func() *http.Request {
			return httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+floorTargetID, nil)
		}},
		{"PUT active=false", func() *http.Request {
			body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"t@example.com","active":false}`
			req := httptest.NewRequest(http.MethodPut, "/scim/v2/Users/"+floorTargetID, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			return req
		}},
		{"PATCH replace active", func() *http.Request {
			body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
				`"Operations":[{"op":"replace","path":"active","value":false}]}`
			req := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+floorTargetID, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			return req
		}},
		{"PATCH pathless active", func() *http.Request {
			body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
				`"Operations":[{"op":"replace","value":{"active":false}}]}`
			req := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+floorTargetID, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			return req
		}},
	}
}

// TestSCIMDeprovision_RefusesStrandingTheDeployment covers all four entry
// points: the target is the deployment's only platform administrator, the
// carrier is empty, and no membership DELETE is queued — so an ordered-agnostic
// mock still fails on an unexpected write if the guard is skipped.
func TestSCIMDeprovision_RefusesStrandingTheDeployment(t *testing.T) {
	for _, tc := range deprovisionRequests() {
		t.Run(tc.name, func(t *testing.T) {
			r, identity, registry := flooredSCIMRouter(t)

			identity.ExpectQuery("(?s)FROM users WHERE id").
				WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}).
					AddRow(floorTargetID, "t@example.com", "Target", nil, time.Now(), time.Now()))

			registry.ExpectBegin()
			registry.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
			// The target is the only admin-bearing membership anywhere.
			identity.ExpectQuery("FROM organization_members").
				WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "scopes"}).
					AddRow("org-1", floorTargetID, []byte(`["admin"]`)))
			registry.ExpectQuery("FROM platform_admins").
				WillReturnRows(sqlmock.NewRows([]string{"user_id"}))
			registry.ExpectRollback()

			w := httptest.NewRecorder()
			r.ServeHTTP(w, tc.req())

			if w.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409 — a refused deprovision must reach the caller, "+
					"not be logged and answered 200: %s", w.Code, w.Body.String())
			}
			var body map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not JSON: %v (%s)", err, w.Body.String())
			}
			detail, _ := body["detail"].(string)
			if !strings.Contains(detail, "last platform administrator") {
				t.Fatalf("detail = %q, want it to name the last platform administrator", detail)
			}
			if err := identity.ExpectationsWereMet(); err != nil {
				t.Errorf("the membership strip must not be attempted: %v", err)
			}
		})
	}
}

// TestSCIMDeprovision_AllowsAnOrdinaryLeaver is the positive control across the
// same four paths. Without it a change that refused every deprovision would
// satisfy the test above and look like a fix.
func TestSCIMDeprovision_AllowsAnOrdinaryLeaver(t *testing.T) {
	for _, tc := range deprovisionRequests() {
		t.Run(tc.name, func(t *testing.T) {
			r, identity, registry := flooredSCIMRouter(t)

			identity.ExpectQuery("(?s)FROM users WHERE id").
				WillReturnRows(sqlmock.NewRows([]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}).
					AddRow(floorTargetID, "t@example.com", "Target", nil, time.Now(), time.Now()))

			registry.ExpectBegin()
			registry.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
			// Somebody else administers the platform.
			identity.ExpectQuery("FROM organization_members").
				WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "scopes"}).
					AddRow("org-9", "someone-else", []byte(`["admin"]`)))
			// The target's own organizations, then each one's state.
			identity.ExpectQuery("SELECT organization_id FROM organization_members").
				WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow("org-1"))
			identity.ExpectQuery("WHERE om.organization_id").
				WillReturnRows(sqlmock.NewRows([]string{"user_id", "scopes"}).
					AddRow(floorTargetID, []byte(`["modules:read"]`)).
					AddRow("owner-1", []byte(`["organizations:write"]`)))
			identity.ExpectQuery("DELETE FROM organization_members").
				WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow("org-1"))
			registry.ExpectRollback()
			// PUT and PATCH also write the user row back.
			identity.ExpectExec("UPDATE users").WillReturnResult(sqlmock.NewResult(0, 1))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, tc.req())

			if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 200/204 — an ordinary leaver must still be "+
					"deprovisioned: %s", w.Code, w.Body.String())
			}
		})
	}
}
