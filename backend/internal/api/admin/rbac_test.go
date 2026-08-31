package admin

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// ---------------------------------------------------------------------------
// Column definitions
// ---------------------------------------------------------------------------

var rtCols = []string{
	"id", "name", "display_name", "description", "scopes", "is_system", "created_at", "updated_at",
}

var approvalCols = []string{
	"id", "mirror_config_id", "organization_id", "requested_by",
	"provider_namespace", "provider_name", "reason", "status",
	"reviewed_by", "reviewed_at", "review_notes", "auto_approved",
	"created_at", "updated_at", "expires_at",
}

var approvalListCols = []string{
	"id", "mirror_config_id", "organization_id", "requested_by",
	"provider_namespace", "provider_name", "reason", "status",
	"reviewed_by", "reviewed_at", "review_notes", "auto_approved",
	"created_at", "updated_at", "expires_at",
	"requested_by_name", "reviewed_by_name", "mirror_name",
}

var mpCols = []string{
	"id", "organization_id", "name", "description", "policy_type",
	"upstream_registry", "namespace_pattern", "provider_pattern",
	"priority", "is_active", "requires_approval", "created_at", "updated_at", "created_by",
}

var mpListCols = []string{
	"id", "organization_id", "name", "description", "policy_type",
	"upstream_registry", "namespace_pattern", "provider_pattern",
	"priority", "is_active", "requires_approval", "created_at", "updated_at", "created_by",
	"organization_name", "created_by_name",
}

var testRTScopes = []byte(`["modules:read","providers:write"]`)

// knownUUID is a constant valid UUID for use in test paths.
const knownUUID = "11111111-1111-1111-1111-111111111111"
const knownUserUUID = "22222222-2222-2222-2222-222222222222"

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

func sampleRTRow() *sqlmock.Rows {
	return sqlmock.NewRows(rtCols).
		AddRow(knownUUID, "reader", "Reader", nil, testRTScopes, false, time.Now(), time.Now())
}

func sampleRTSystemRow() *sqlmock.Rows {
	return sqlmock.NewRows(rtCols).
		AddRow(knownUUID, "admin", "Admin", nil, testRTScopes, true, time.Now(), time.Now())
}

func emptyRTRows() *sqlmock.Rows {
	return sqlmock.NewRows(rtCols)
}

func sampleApprovalRow() *sqlmock.Rows {
	return sqlmock.NewRows(approvalCols).
		AddRow(
			knownUUID, knownUUID, nil, nil,
			"hashicorp", nil, "need it", "pending",
			nil, nil, nil, false,
			time.Now(), time.Now(), nil,
		)
}

func emptyApprovalRows() *sqlmock.Rows {
	return sqlmock.NewRows(approvalCols)
}

func emptyApprovalListRows() *sqlmock.Rows {
	return sqlmock.NewRows(approvalListCols)
}

func emptyMPListRows() *sqlmock.Rows {
	return sqlmock.NewRows(mpListCols)
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

// expectApprovalConfigLookup primes the mirror-configuration read that
// CreateApprovalRequest performs to derive the approval row's owning
// organization from the CONFIG rather than from the requester (issue #719,
// GUARD approval-create-config-org). The row is returned unowned; the tests
// using it run as a platform administrator, for whom that resolves.
func expectApprovalConfigLookup(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("SELECT.*FROM mirror_configurations.*WHERE id").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols).AddRow(
			knownUUID, "cfg", nil, "https://registry.terraform.io", nil,
			nil, nil, nil, nil, true, 24, nil, nil, nil,
			time.Now(), time.Now(), nil))
}

func newRBACRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	return newRBACRouterWithRevocation(t, false)
}

// newRBACRouterWithRevocation builds the same router as newRBACRouter but, when
// withRevocation is true, also wires a UserTokenRevocationRepository over the
// same mocked connection, so tests can assert on the revocation-sweep calls
// described in issue #559 finding [9].
func newRBACRouterWithRevocation(t *testing.T, withRevocation bool) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	rbacRepo := repositories.NewRBACRepository(sqlxDB)
	var userRevocations *repositories.UserTokenRevocationRepository
	var apiKeys *repositories.APIKeyRepository
	if withRevocation {
		userRevocations = repositories.NewUserTokenRevocationRepository(db)
		// The API-key half of the sweep (issue #732) runs over the same mocked
		// connection, so the org-bound key lookup/delete are ordinary
		// expectations on `mock` like the watermark write.
		apiKeys = repositories.NewAPIKeyRepository(db)
	}
	h := NewRBACHandlers(rbacRepo, userRevocations, apiKeys).
		WithOrgRepo(repositories.NewOrganizationRepository(db)).
		// CreateApprovalRequest resolves the owning organization of the mirror
		// configuration named in the body before writing the row (issue #719),
		// so the handler needs the mirror repository wired here too.
		WithMirrorRepo(repositories.NewMirrorRepository(sqlxDB)).
		// Matches production topology (router.go), which always wires the
		// identity connection: PreviewRoleTemplateReconciliation's own
		// "not wired" 503 path is covered separately, by a router built
		// without this call.
		WithIdentityDB(db)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", knownUserUUID)
		// Platform admin: these tests cover RBAC/approval/policy mechanics, not
		// tenancy, and admin is the principal every #719 tenant-scope guard
		// deliberately exempts. Cross-tenant behaviour for the list axes is
		// owned by tenant_scope_class_test.go, and for the /:id axes by
		// internal/api/mirror_approval_routes_test.go.
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Next()
	})

	r.GET("/role-templates", h.ListRoleTemplates)
	r.GET("/role-templates/:id", h.GetRoleTemplate)
	r.POST("/role-templates", h.CreateRoleTemplate)
	r.PUT("/role-templates/:id", h.UpdateRoleTemplate)
	r.DELETE("/role-templates/:id", h.DeleteRoleTemplate)
	r.POST("/role-templates/:id/reconcile-preview", h.PreviewRoleTemplateReconciliation)

	r.GET("/approvals", h.ListApprovalRequests)
	r.GET("/approvals/:id", h.GetApprovalRequest)
	r.POST("/approvals", h.CreateApprovalRequest)
	r.PUT("/approvals/:id/review", h.ReviewApproval)

	r.GET("/policies", h.ListMirrorPolicies)
	r.GET("/policies/:id", h.GetMirrorPolicy)
	r.POST("/policies", h.CreateMirrorPolicy)
	r.PUT("/policies/:id", h.UpdateMirrorPolicy)
	r.DELETE("/policies/:id", h.DeleteMirrorPolicy)
	r.POST("/policies/evaluate", h.EvaluatePolicy)

	return mock, r
}

// ---------------------------------------------------------------------------
// ListRoleTemplates
// ---------------------------------------------------------------------------

func TestRBACListRoleTemplates_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates.*ORDER BY").
		WillReturnRows(sampleRTRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACListRoleTemplates_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates").WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetRoleTemplate
// ---------------------------------------------------------------------------

func TestRBACGetRoleTemplate_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACGetRoleTemplate_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(emptyRTRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRBACGetRoleTemplate_Found(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateRoleTemplate
// ---------------------------------------------------------------------------

func TestRBACCreateRoleTemplate_MissingFields(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACCreateRoleTemplate_Conflict(t *testing.T) {
	mock, r := newRBACRouter(t)
	// GetRoleTemplateByName finds existing
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE name").
		WillReturnRows(sampleRTRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates",
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACCreateRoleTemplate_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE name").
		WillReturnRows(emptyRTRows())
	mock.ExpectExec("INSERT INTO role_templates").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates",
		jsonBody(map[string]interface{}{
			"name":         "new-role",
			"display_name": "New Role",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// TestRBACRoleTemplates_RefuseTheAdminScope closes the way back (issue #766,
// migration 000054).
//
// The migration takes `admin` off every role template and the membership writes
// refuse an admin-bearing one — but this is the route by which a role template
// gets its scopes, so leaving it open would let the same principal put back,
// the same afternoon, exactly what the migration removed. The removal would be
// a one-time cleanup rather than a property.
//
// Both verbs, because PUT is a write of the same field. No repository
// expectation is queued: the refusal happens before the name/id lookup, so an
// ordered mock also proves nothing reached the database.
func TestRBACRoleTemplates_RefuseTheAdminScope(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"create", http.MethodPost, "/role-templates"},
		{"update", http.MethodPut, "/role-templates/" + knownUUID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, r := newRBACRouter(t)
			if tt.method == http.MethodPut {
				// Update reads the existing row and refuses system templates
				// before it binds the body, so this one lookup is legitimate.
				mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
					WillReturnRows(sampleRTRow())
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path,
				jsonBody(map[string]interface{}{
					"name":         "superuser",
					"display_name": "Superuser",
					"scopes":       []string{"modules:read", "admin"},
				})))

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — a role template must not be able to carry the "+
					"platform-wide `admin` scope, or migration 000054's removal is a one-time "+
					"cleanup rather than a property (#766): body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "admin/platform-admins") {
				t.Errorf("body = %s, want the refusal to name the route that DOES grant platform "+
					"administration", w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet/unexpected expectations (the refusal must not write): %v", err)
			}
		})
	}
}

// TestRBACRoleTemplates_StillAcceptOrdinaryScopes is the positive control: a
// refusal that rejected every scope list would satisfy the test above.
func TestRBACRoleTemplates_StillAcceptOrdinaryScopes(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE name").
		WillReturnRows(emptyRTRows())
	mock.ExpectExec("INSERT INTO role_templates").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/role-templates",
		jsonBody(map[string]interface{}{
			"name":         "almost-admin",
			"display_name": "Almost Admin",
			"scopes":       []string{"organizations:write", "users:write", "audit:read"},
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateRoleTemplate
// ---------------------------------------------------------------------------

func TestRBACUpdateRoleTemplate_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(emptyRTRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRBACUpdateRoleTemplate_SystemTemplate(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTSystemRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "admin",
			"display_name": "Admin",
			"scopes":       []string{"admin"},
		})))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateRoleTemplate_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// Issue #559 finding [9] plus issue #732: editing a role template's scopes must
// sweep BOTH credential families that snapshot those scopes for every member
// currently assigned the template — the JWT revoke-all watermark and the
// member's API keys in the organization where they hold it — so the new scopes
// take effect immediately rather than waiting out the JWT TTL (JWTs) or never
// (keys).
func TestRBACUpdateRoleTemplate_ScopesChanged_RevokesMemberTokens(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)
	logs := captureSlogOutput(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow()) // scopes = testRTScopes = ["modules:read","providers:write"]
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_member_roles WHERE role_template_id").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "organization_id"}).
			AddRow("member-1", "org-1").
			AddRow("member-2", "org-2"))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("member-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// member-1's key asks for providers:write, which the narrowed template no
	// longer grants → deleted.
	expectOrgKeySweepScoped(mock, "member-1", "org-1", "key-m1", []byte(`["providers:write"]`))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("member-2").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// member-2's key asks only for modules:read, which the new template still
	// grants → listed but NOT deleted. Deleting it would destroy a working,
	// unrecoverable credential that is entirely within the member's remaining
	// authority; no DELETE is registered, so sqlmock fails the test if one is
	// issued.
	expectOrgKeyList(mock, "member-2", "org-2", "key-m2", []byte(`["modules:read"]`))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			"scopes":       []string{"modules:read"}, // narrower than testRTScopes
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("revocation sweep was not issued: %v", err)
	}
	// member-2's key must not be touched at all. Asserted on the logs rather
	// than on sqlmock: an unregistered DELETE is returned to the sweeper as an
	// error, which its best-effort handling logs and swallows, so
	// ExpectationsWereMet() would still pass. The sweeper names the key in
	// both its success and its failure log, so the id appearing at all means
	// a deletion was attempted.
	if strings.Contains(logs.String(), "key-m2") {
		t.Errorf("a key entirely within the retained authority was swept; logs: %s", logs.String())
	}
}

// A scope WIDENING must not sweep anything. Every credential frozen under the
// old, narrower template still asks for no more than its holder now has, so
// revoking sessions and irreversibly deleting API keys would destroy working
// credentials fleet-wide as a side effect of GRANTING permission. Asserted by
// registering no member-lookup or revocation expectations: sqlmock fails the
// test if the handler issues any.
func TestRBACUpdateRoleTemplate_ScopesWidened_SkipsRevocation(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)
	logs := captureSlogOutput(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow()) // scopes = testRTScopes = ["modules:read","providers:write"]
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			// A strict superset: everything the template granted before, plus
			// modules:write.
			"scopes": []string{"modules:read", "providers:write", "modules:write"},
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	assertNoSweepAttempted(t, mock, logs, "a scope widening")
}

// assertNoSweepAttempted fails when the handler tried to sweep at all.
//
// mock.ExpectationsWereMet() alone is NOT sufficient here: sqlmock only checks
// that every REGISTERED expectation fired, so an unexpected extra statement is
// returned to the caller as an error and then swallowed by the sweep's
// deliberate best-effort error handling, leaving the test green. The member
// lookup is the sweep's first statement, so its failure log is the reliable
// signal that a sweep was attempted.
func assertNoSweepAttempted(t *testing.T, mock sqlmock.Sqlmock, logs *bytes.Buffer, what string) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("%s must not sweep any credential: %v", what, err)
	}
	if strings.Contains(logs.String(), "failed to list role template members for credential revocation") {
		t.Errorf("%s attempted a credential sweep; logs: %s", what, logs.String())
	}
}

// A pure REORDERING of an unchanged scope set must not sweep anything either.
// The previous gate compared the two slices index-wise, so swapping two
// entries in the UI read as a scope change and hard-deleted every affected
// member's org-bound API keys.
func TestRBACUpdateRoleTemplate_ScopesReordered_SkipsRevocation(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)
	logs := captureSlogOutput(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow()) // scopes = testRTScopes = ["modules:read","providers:write"]
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			"scopes":       []string{"providers:write", "modules:read"}, // same set, swapped
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	assertNoSweepAttempted(t, mock, logs, "a pure reordering")
}

// A display-name/description-only edit that leaves scopes unchanged must not
// trigger a revocation sweep — asserted by NOT registering the member-lookup
// or revocation expectations: sqlmock fails the test if the handler runs an
// unexpected query or exec.
func TestRBACUpdateRoleTemplate_ScopesUnchanged_SkipsRevocation(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow()) // scopes = testRTScopes = ["modules:read","providers:write"]
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			"scopes":       []string{"modules:read", "providers:write"}, // same as testRTScopes
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected mock call: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteRoleTemplate
// ---------------------------------------------------------------------------

func TestRBACDeleteRoleTemplate_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(emptyRTRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRBACDeleteRoleTemplate_SystemTemplate(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTSystemRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACDeleteRoleTemplate_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectExec("DELETE FROM role_templates WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// Deleting a role template unconditionally strips its scopes from every
// member who held it, so — unlike an edit — there's no "was this a no-op"
// question to gate revocation on: every affected member's tokens must be
// revoked (issue #559 finding [9]).
func TestRBACDeleteRoleTemplate_RevokesMemberTokens(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_member_roles WHERE role_template_id").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "organization_id"}).
			AddRow("member-1", "org-1").
			AddRow("member-2", "org-2"))
	mock.ExpectExec("DELETE FROM role_templates WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("member-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	expectOrgKeySweep(mock, "member-1", "org-1", "key-m1")
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("member-2").
		WillReturnResult(sqlmock.NewResult(1, 1))
	expectOrgKeySweep(mock, "member-2", "org-2", "key-m2")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("revocation sweep was not issued: %v", err)
	}
}

// The pre-delete member lookup only feeds the best-effort revocation sweep;
// it is not a precondition for the deletion itself. A failure there must be
// logged and swallowed, not turned into a 500 that blocks removing an
// over-privileged or compromised role template.
func TestRBACDeleteRoleTemplate_MemberLookupDBError_StillDeletes(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_member_roles WHERE role_template_id").
		WillReturnError(errDB)
	mock.ExpectExec("DELETE FROM role_templates WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even though the member lookup failed: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected extra calls (no member list means no revocation attempts): %v", err)
	}
	var body struct {
		RevocationIncomplete bool `json:"revocation_incomplete"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body: %v: body=%s", err, w.Body.String())
	}
	if !body.RevocationIncomplete {
		t.Errorf("expected revocation_incomplete=true in the response, got body=%s", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// PreviewRoleTemplateReconciliation (issue #282)
// ---------------------------------------------------------------------------

// previewJoinCols matches identitystore's templateAffectedWithKeysQuery
// column list: organization_id, user_id, then the LEFT JOINed api_keys id and
// scopes (NULL on both when the principal holds no key at all).
var previewJoinCols = []string{"organization_id", "user_id", "id", "scopes"}

func TestRBACPreviewRoleTemplateReconciliation_InvalidID(t *testing.T) {
	_, r := newRBACRouterWithRevocation(t, false)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates/not-a-uuid/reconcile-preview", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACPreviewRoleTemplateReconciliation_NotFound(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, false)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(emptyRTRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates/"+knownUUID+"/reconcile-preview",
		jsonBody(map[string]interface{}{"scopes": []string{"modules:read"}})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// GUARD preview-not-wired-is-503-not-panic. A deployment (or a test) that
// constructs RBACHandlers without WithIdentityDB must refuse cleanly rather
// than dereference a nil *sql.DB.
func TestRBACPreviewRoleTemplateReconciliation_IdentityDBNotWired(t *testing.T) {
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	rbacRepo := repositories.NewRBACRepository(sqlxDB)
	h := NewRBACHandlers(rbacRepo, nil, nil) // deliberately no WithIdentityDB

	r := gin.New()
	r.POST("/role-templates/:id/reconcile-preview", h.PreviewRoleTemplateReconciliation)

	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates/"+knownUUID+"/reconcile-preview", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503: body=%s", w.Code, w.Body.String())
	}
}

// GUARD preview-computes-scanned-principals-keys. Four principals hold the
// template: one whose key is a SUBSET of the narrowed scopes (retained), one
// whose key EXCEEDS them (swept), one with NO api_keys row at all (counted in
// Scanned, not in Principals/Keys), and one in a SECOND organization whose key
// also exceeds them (swept) -- proving the join is not accidentally scoped to
// one organization or blind to keyless holders.
func TestRBACPreviewRoleTemplateReconciliation_ComputesImpact(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, false)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectQuery(`(?s)FROM organization_members om.*LEFT JOIN api_keys ak.*WHERE om\.role_template_id`).
		WithArgs(knownUUID).
		WillReturnRows(sqlmock.NewRows(previewJoinCols).
			AddRow("org-1", "user-subset", "key-subset", []byte(`["modules:read"]`)).
			AddRow("org-1", "user-over", "key-over", []byte(`["providers:write"]`)).
			AddRow("org-1", "user-keyless", nil, nil).
			AddRow("org-2", "user-over-b", "key-over-b", []byte(`["providers:write"]`)))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates/"+knownUUID+"/reconcile-preview",
		jsonBody(map[string]interface{}{"scopes": []string{"modules:read"}})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	var impact RoleTemplateReconciliationImpact
	if err := json.Unmarshal(w.Body.Bytes(), &impact); err != nil {
		t.Fatalf("decode: %v: body=%s", err, w.Body.String())
	}
	if impact.Scanned != 4 {
		t.Errorf("Scanned = %d, want 4 (every holder, keyed or not)", impact.Scanned)
	}
	if impact.Principals != 2 {
		t.Errorf("Principals = %d, want 2 (user-over, user-over-b)", impact.Principals)
	}
	if impact.Keys != 2 {
		t.Errorf("Keys = %d, want 2 (key-over, key-over-b -- key-subset survives, user-keyless has none)", impact.Keys)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// GUARD preview-omitted-scopes-means-deletion. No body at all previews what
// DELETING the template would sweep: proposedScopes is nil, so nothing is
// retained and every existing key is swept -- matching how
// PreviewRoleTemplateReconciliationRequest's own doc comment says nil/empty
// scopes must be read.
func TestRBACPreviewRoleTemplateReconciliation_OmittedScopesPreviewsADeletion(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, false)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectQuery(`(?s)FROM organization_members om.*LEFT JOIN api_keys ak`).
		WithArgs(knownUUID).
		WillReturnRows(sqlmock.NewRows(previewJoinCols).
			AddRow("org-1", "user-any", "key-any", []byte(`["modules:read"]`)))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates/"+knownUUID+"/reconcile-preview", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	var impact RoleTemplateReconciliationImpact
	if err := json.Unmarshal(w.Body.Bytes(), &impact); err != nil {
		t.Fatalf("decode: %v: body=%s", err, w.Body.String())
	}
	if impact.Keys != 1 || impact.Principals != 1 {
		t.Errorf("got Principals=%d Keys=%d, want 1/1 (empty proposed scopes retains nothing)", impact.Principals, impact.Keys)
	}
}

// GUARD preview-agrees-with-the-real-sweep. The central promise this endpoint
// makes: for the SAME template, the SAME proposed scopes, and a consistent
// fixture (identity's organization_members and registry's
// organization_member_roles mirror agreeing -- the steady state both tables
// are dual-written to maintain, see the caveat on
// PreviewRoleTemplateReconciliation), the preview's Keys count matches
// exactly how many api_keys rows the REAL PUT deletes, driven through the
// real HTTP handlers exactly as an admin UI would call them: preview, then
// save.
func TestRBACPreviewRoleTemplateReconciliation_AgreesWithRealSweep(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)

	// --- Step 1: preview narrowing the template to ["modules:read"] ---
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow()) // current scopes = ["modules:read","providers:write"]
	mock.ExpectQuery(`(?s)FROM organization_members om.*LEFT JOIN api_keys ak.*WHERE om\.role_template_id`).
		WithArgs(knownUUID).
		WillReturnRows(sqlmock.NewRows(previewJoinCols).
			AddRow("org-1", "member-1", "key-m1", []byte(`["providers:write"]`)).
			AddRow("org-2", "member-2", "key-m2", []byte(`["modules:read"]`)))

	previewW := httptest.NewRecorder()
	r.ServeHTTP(previewW, httptest.NewRequest("POST", "/role-templates/"+knownUUID+"/reconcile-preview",
		jsonBody(map[string]interface{}{"scopes": []string{"modules:read"}})))
	if previewW.Code != http.StatusOK {
		t.Fatalf("preview status = %d, want 200: body=%s", previewW.Code, previewW.Body.String())
	}
	var impact RoleTemplateReconciliationImpact
	if err := json.Unmarshal(previewW.Body.Bytes(), &impact); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if impact.Keys != 1 {
		t.Fatalf("preview Keys = %d, want 1 (member-1's key-m1 only)", impact.Keys)
	}

	// --- Step 2: the same change, actually saved through the real PUT --
	// the same (org, user) pairs, this time read from registry's own mirror,
	// which is what UpdateRoleTemplate's existing sweep actually runs through.
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_member_roles WHERE role_template_id").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "organization_id"}).
			AddRow("member-1", "org-1").
			AddRow("member-2", "org-2"))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("member-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	expectOrgKeySweepScoped(mock, "member-1", "org-1", "key-m1", []byte(`["providers:write"]`))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("member-2").
		WillReturnResult(sqlmock.NewResult(1, 1))
	expectOrgKeyList(mock, "member-2", "org-2", "key-m2", []byte(`["modules:read"]`))

	putW := httptest.NewRecorder()
	r.ServeHTTP(putW, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			"scopes":       []string{"modules:read"},
		})))
	if putW.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200: body=%s", putW.Code, putW.Body.String())
	}
	// ExpectationsWereMet proves exactly one DELETE FROM api_keys ran
	// (registered once, by expectOrgKeySweepScoped for member-1) and none for
	// member-2 -- the same single-key count the preview promised in step 1.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("real sweep did not match what the preview promised: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListApprovalRequests
// ---------------------------------------------------------------------------

func TestRBACListApprovals_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests.*WHERE 1").
		WillReturnRows(emptyApprovalListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACListApprovals_InvalidOrgID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals?organization_id=not-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetApprovalRequest
// ---------------------------------------------------------------------------

func TestRBACGetApproval_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACGetApproval_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnRows(emptyApprovalRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateApprovalRequest
// ---------------------------------------------------------------------------

func TestRBACCreateApproval_MissingFields(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACCreateApproval_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	expectApprovalConfigLookup(mock)
	mock.ExpectExec("INSERT INTO mirror_approval_requests").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   knownUUID,
			"provider_namespace": "hashicorp",
			"reason":             "need it",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ReviewApproval
// ---------------------------------------------------------------------------

func TestRBACReviewApproval_InvalidStatus(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "invalid-status"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACReviewApproval_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("UPDATE mirror_approval_requests.*SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnRows(sampleApprovalRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "approved", "notes": "looks good"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListMirrorPolicies
// ---------------------------------------------------------------------------

func TestRBACListMirrorPolicies_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(emptyMPListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACListMirrorPolicies_InvalidOrgID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies?organization_id=not-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetMirrorPolicy
// ---------------------------------------------------------------------------

func TestRBACGetMirrorPolicy_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sqlmock.NewRows(mpCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateMirrorPolicy
// ---------------------------------------------------------------------------

func TestRBACCreateMirrorPolicy_MissingFields(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACCreateMirrorPolicy_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("INSERT INTO mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":        "allow-all",
			"policy_type": "allow",
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateMirrorPolicy
// ---------------------------------------------------------------------------

func TestRBACUpdateMirrorPolicy_NotFound(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sqlmock.NewRows(mpCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":        "updated",
			"policy_type": "allow",
		})))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteMirrorPolicy
// ---------------------------------------------------------------------------

func TestRBACDeleteMirrorPolicy_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/policies/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACDeleteMirrorPolicy_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("DELETE FROM mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/policies/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// EvaluatePolicy
// ---------------------------------------------------------------------------

func TestRBACEvaluatePolicy_MissingFields(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACEvaluatePolicy_NoPolicies(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(emptyMPListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{
			"registry":  "registry.terraform.io",
			"namespace": "hashicorp",
			"provider":  "aws",
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["allowed"] != false {
		t.Errorf("expected allowed=false when no policies, got %v", resp["allowed"])
	}
}

// unused import guard
var _ = sql.ErrNoRows

// ---------------------------------------------------------------------------
// UpdateMirrorPolicy — additional paths
// ---------------------------------------------------------------------------

func sampleMPRow() *sqlmock.Rows {
	return sqlmock.NewRows(mpCols).AddRow(
		knownUUID, nil, "allow-all", nil, "allow",
		nil, nil, nil,
		10, true, false, time.Now(), time.Now(), nil,
	)
}

func TestRBACUpdateMirrorPolicy_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/not-a-uuid",
		jsonBody(map[string]interface{}{"name": "x", "policy_type": "allow"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACUpdateMirrorPolicy_GetDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "x", "policy_type": "allow"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateMirrorPolicy_InvalidPolicyType(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sampleMPRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "x", "policy_type": "invalid"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateMirrorPolicy_UpdateDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sampleMPRow())
	mock.ExpectExec("UPDATE mirror_policies").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "updated", "policy_type": "deny"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateMirrorPolicy_Success(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sampleMPRow())
	mock.ExpectExec("UPDATE mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "updated", "policy_type": "allow"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// EvaluatePolicy — additional branches
// ---------------------------------------------------------------------------

func TestRBACEvaluatePolicy_InvalidOrgID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate?organization_id=not-a-uuid",
		jsonBody(map[string]interface{}{"registry": "registry.terraform.io", "namespace": "hashicorp", "provider": "aws"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACEvaluatePolicy_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{"registry": "registry.terraform.io", "namespace": "hashicorp", "provider": "aws"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetMirrorPolicy — additional branches
// ---------------------------------------------------------------------------

func TestRBACGetMirrorPolicy_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateMirrorPolicy — additional branches
// ---------------------------------------------------------------------------

func TestRBACCreateMirrorPolicy_InvalidPolicyType(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":        "bad-type",
			"policy_type": "invalid",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACCreateMirrorPolicy_InvalidOrgID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":            "test",
			"policy_type":     "allow",
			"organization_id": "not-a-uuid",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACCreateMirrorPolicy_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("INSERT INTO mirror_policies").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":        "test",
			"policy_type": "allow",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListMirrorPolicies — additional branches
// ---------------------------------------------------------------------------

func TestRBACListMirrorPolicies_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteRoleTemplate — additional branches
// ---------------------------------------------------------------------------

func TestRBACDeleteRoleTemplate_GetDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACDeleteRoleTemplate_DeleteDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectExec("DELETE FROM role_templates WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListApprovalRequests — additional branches
// ---------------------------------------------------------------------------

func TestRBACListApprovals_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateApprovalRequest — additional branches
// ---------------------------------------------------------------------------

func TestRBACCreateApproval_InvalidMirrorConfigID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   "not-a-uuid",
			"provider_namespace": "hashicorp",
		})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACCreateApproval_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	expectApprovalConfigLookup(mock)
	mock.ExpectExec("INSERT INTO mirror_approval_requests").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   knownUUID,
			"provider_namespace": "hashicorp",
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ReviewApproval — additional branches
// ---------------------------------------------------------------------------

func TestRBACReviewApproval_UpdateDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("UPDATE mirror_approval_requests.*SET status").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "approved", "notes": "ok"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACReviewApproval_GetDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("UPDATE mirror_approval_requests.*SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "rejected", "notes": "no"})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Router helper with organization_id in context
// ---------------------------------------------------------------------------

func newRBACRouterWithOrg(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	rbacRepo := repositories.NewRBACRepository(sqlxDB)
	h := NewRBACHandlers(rbacRepo, nil, nil).
		WithOrgRepo(repositories.NewOrganizationRepository(db)).
		WithMirrorRepo(repositories.NewMirrorRepository(sqlxDB))

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", knownUserUUID)
		// A DIFFERENT organization from the one owning the mirror config the
		// test files against. Before #719's approval-create-config-org guard the
		// row was stamped with this ambient value; it must now come from the
		// configuration instead.
		c.Set("organization_id", knownUserUUID)
		c.Set("scopes", []string{string(auth.ScopeMirrorsManage)})
		c.Next()
	})

	r.POST("/approvals", h.CreateApprovalRequest)

	return mock, r
}

// ---------------------------------------------------------------------------
// GetRoleTemplate — DB error
// ---------------------------------------------------------------------------

func TestRBACGetRoleTemplate_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateRoleTemplate — additional error paths
// ---------------------------------------------------------------------------

func TestRBACCreateRoleTemplate_GetByNameDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE name").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates",
		jsonBody(map[string]interface{}{
			"name":         "new-role",
			"display_name": "New Role",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACCreateRoleTemplate_CreateDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE name").
		WillReturnRows(emptyRTRows())
	mock.ExpectExec("INSERT INTO role_templates").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/role-templates",
		jsonBody(map[string]interface{}{
			"name":         "new-role",
			"display_name": "New Role",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateRoleTemplate — additional error paths
// ---------------------------------------------------------------------------

func TestRBACUpdateRoleTemplate_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/not-a-uuid",
		jsonBody(map[string]interface{}{"name": "x", "display_name": "X", "scopes": []string{"a"}})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACUpdateRoleTemplate_GetDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{"name": "x", "display_name": "X", "scopes": []string{"a"}})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateRoleTemplate_BindJSONError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACUpdateRoleTemplate_UpdateDBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteRoleTemplate — invalid ID
// ---------------------------------------------------------------------------

func TestRBACDeleteRoleTemplate_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ListApprovalRequests — filter paths
// ---------------------------------------------------------------------------

func TestRBACListApprovals_WithStatusFilter(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests.*WHERE 1").
		WillReturnRows(emptyApprovalListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals?status=pending", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACListApprovals_WithValidOrgID(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests.*WHERE 1").
		WillReturnRows(emptyApprovalListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals?organization_id="+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetApprovalRequest — additional paths
// ---------------------------------------------------------------------------

func TestRBACGetApproval_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACGetApproval_Found(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnRows(sampleApprovalRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/approvals/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateApprovalRequest — with organization_id in context
// ---------------------------------------------------------------------------

// TestRBACCreateApproval_OrgComesFromConfigNotContext pins GUARD
// approval-create-config-org (issue #719). The approval row's organization used
// to be read from the REQUESTER's ambient context, so a caller could file a
// request against another organization's mirror configuration and have the row
// stamped as their own — after which every downstream per-org guard, including
// the one on POST /approvals/:id/token, agreed it was theirs.
//
// The row's tenancy must be derived from the configuration it points at.
func TestRBACCreateApproval_OrgComesFromConfigNotContext(t *testing.T) {
	mock, r := newRBACRouterWithOrg(t)
	// The configuration belongs to knownUUID; the caller's ambient
	// organization_id is knownUserUUID.
	mock.ExpectQuery("SELECT.*FROM mirror_configurations.*WHERE id").
		WillReturnRows(sqlmock.NewRows(mirrorCfgCols).AddRow(
			knownUUID, "cfg", nil, "https://registry.terraform.io", knownUUID,
			nil, nil, nil, nil, true, 24, nil, nil, nil,
			time.Now(), time.Now(), nil))
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(sqlmock.NewRows(membershipCols).AddRow(
			knownUUID, "Owner", "role-1", time.Now(),
			"devops", "DevOps", []byte(`["mirrors:manage"]`)))
	expectRegistryRolesForUser(mock, registryRole{
		orgID: knownUUID, id: "role-1", name: "devops", displayName: "DevOps",
		scopes: `["mirrors:manage"]`,
	})
	mock.ExpectExec("INSERT INTO mirror_approval_requests").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   knownUUID,
			"provider_namespace": "hashicorp",
			"reason":             "need it",
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["organization_id"] != knownUUID {
		t.Errorf("organization_id = %v, want %s (the mirror configuration's owner, "+
			"not the caller's ambient organization) — guard "+
			"approval-create-config-org missing?", resp["organization_id"], knownUUID)
	}
}

// ---------------------------------------------------------------------------
// ReviewApproval — additional error paths
// ---------------------------------------------------------------------------

func TestRBACReviewApproval_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/not-a-uuid/review",
		jsonBody(map[string]interface{}{"status": "approved"})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACReviewApproval_MissingBody(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ListMirrorPolicies — with valid org ID
// ---------------------------------------------------------------------------

func TestRBACListMirrorPolicies_WithValidOrgID(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(emptyMPListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies?organization_id="+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetMirrorPolicy — additional paths
// ---------------------------------------------------------------------------

func TestRBACGetMirrorPolicy_InvalidID(t *testing.T) {
	_, r := newRBACRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies/not-a-uuid", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRBACGetMirrorPolicy_Found(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sampleMPRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/policies/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateMirrorPolicy — with valid organization ID in body
// ---------------------------------------------------------------------------

func TestRBACCreateMirrorPolicy_WithValidOrgID(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("INSERT INTO mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":            "allow-org",
			"policy_type":     "allow",
			"organization_id": knownUUID,
		})))

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// UpdateMirrorPolicy — bind error
// ---------------------------------------------------------------------------

func TestRBACUpdateMirrorPolicy_BindJSONError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies WHERE id").
		WillReturnRows(sampleMPRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/policies/"+knownUUID,
		jsonBody(map[string]interface{}{})))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteMirrorPolicy — DB error
// ---------------------------------------------------------------------------

func TestRBACDeleteMirrorPolicy_DBError(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("DELETE FROM mirror_policies").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/policies/"+knownUUID, nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// EvaluatePolicy — with valid organization ID
// ---------------------------------------------------------------------------

func TestRBACEvaluatePolicy_WithValidOrgID(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(emptyMPListRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate?organization_id="+knownUUID,
		jsonBody(map[string]interface{}{
			"registry":  "registry.terraform.io",
			"namespace": "hashicorp",
			"provider":  "aws",
		})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Router helper without user_id in context (tests absent-context paths)
// ---------------------------------------------------------------------------

func newRBACRouterNoUser(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	rbacRepo := repositories.NewRBACRepository(sqlxDB)
	h := NewRBACHandlers(rbacRepo, nil, nil).
		WithOrgRepo(repositories.NewOrganizationRepository(db)).
		WithMirrorRepo(repositories.NewMirrorRepository(sqlxDB))

	r := gin.New()
	// No user_id — exercises the context-absent code paths (an API-key
	// principal with no user binding). The admin scope is still installed:
	// since #719 every create axis here resolves a tenant scope, and "no
	// principal at all may create rows" is the guard working, not a fixture.
	r.Use(func(c *gin.Context) { c.Set("scopes", []string{string(auth.ScopeAdmin)}) })

	r.POST("/approvals", h.CreateApprovalRequest)
	r.PUT("/approvals/:id/review", h.ReviewApproval)
	r.POST("/policies", h.CreateMirrorPolicy)

	return mock, r
}

// ---------------------------------------------------------------------------
// CreateApprovalRequest — user_id extraction verified in response
// ---------------------------------------------------------------------------

func TestRBACCreateApproval_ResponseIncludesRequestedBy(t *testing.T) {
	mock, r := newRBACRouter(t)
	expectApprovalConfigLookup(mock)
	mock.ExpectExec("INSERT INTO mirror_approval_requests").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   knownUUID,
			"provider_namespace": "hashicorp",
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["requested_by"] != knownUserUUID {
		t.Errorf("requested_by = %v, want %s", resp["requested_by"], knownUserUUID)
	}
}

func TestRBACCreateApproval_NoUserInContext(t *testing.T) {
	mock, r := newRBACRouterNoUser(t)
	expectApprovalConfigLookup(mock)
	mock.ExpectExec("INSERT INTO mirror_approval_requests").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   knownUUID,
			"provider_namespace": "hashicorp",
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if _, exists := resp["requested_by"]; exists {
		t.Errorf("expected no requested_by when user_id absent from context, got %v", resp["requested_by"])
	}
}

func TestRBACCreateApproval_WithProviderName(t *testing.T) {
	mock, r := newRBACRouter(t)
	expectApprovalConfigLookup(mock)
	mock.ExpectExec("INSERT INTO mirror_approval_requests").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/approvals",
		jsonBody(map[string]interface{}{
			"mirror_config_id":   knownUUID,
			"provider_namespace": "hashicorp",
			"provider_name":      "aws",
			"reason":             "need aws provider",
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["provider_name"] != "aws" {
		t.Errorf("provider_name = %v, want aws", resp["provider_name"])
	}
}

// ---------------------------------------------------------------------------
// ReviewApproval — reviewer_id extraction from context
// ---------------------------------------------------------------------------

func TestRBACReviewApproval_RejectedSuccess(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("UPDATE mirror_approval_requests.*SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnRows(sampleApprovalRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "rejected", "notes": "not needed"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

func TestRBACReviewApproval_NoUserInContext(t *testing.T) {
	mock, r := newRBACRouterNoUser(t)
	mock.ExpectExec("UPDATE mirror_approval_requests.*SET status").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT.*FROM mirror_approval_requests WHERE id").
		WillReturnRows(sampleApprovalRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/approvals/"+knownUUID+"/review",
		jsonBody(map[string]interface{}{"status": "approved", "notes": "ok"})))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateMirrorPolicy — created_by extraction from context
// ---------------------------------------------------------------------------

func TestRBACCreateMirrorPolicy_ResponseIncludesCreatedBy(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectExec("INSERT INTO mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":        "allow-all",
			"policy_type": "allow",
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["created_by"] != knownUserUUID {
		t.Errorf("created_by = %v, want %s", resp["created_by"], knownUserUUID)
	}
}

func TestRBACCreateMirrorPolicy_NoUserInContext(t *testing.T) {
	mock, r := newRBACRouterNoUser(t)
	mock.ExpectExec("INSERT INTO mirror_policies").
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies",
		jsonBody(map[string]interface{}{
			"name":        "allow-all",
			"policy_type": "allow",
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if _, exists := resp["created_by"]; exists {
		t.Errorf("expected no created_by when user_id absent from context, got %v", resp["created_by"])
	}
}

// ---------------------------------------------------------------------------
// EvaluatePolicy — full evaluation flow
// ---------------------------------------------------------------------------

func TestRBACEvaluatePolicy_AllowPolicyMatch(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(sqlmock.NewRows(mpListCols).AddRow(
			knownUUID, nil, "allow-all", nil, "allow",
			nil, nil, nil,
			10, true, false, time.Now(), time.Now(), nil,
			"Global", "",
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{
			"registry":  "registry.terraform.io",
			"namespace": "hashicorp",
			"provider":  "aws",
		})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["allowed"] != true {
		t.Errorf("allowed = %v, want true", resp["allowed"])
	}
	reason, _ := resp["reason"].(string)
	if reason != "Allowed by policy: allow-all" {
		t.Errorf("reason = %q, want %q", reason, "Allowed by policy: allow-all")
	}
}

func TestRBACEvaluatePolicy_DenyPolicyMatch(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(sqlmock.NewRows(mpListCols).AddRow(
			knownUUID, nil, "deny-all", nil, "deny",
			nil, nil, nil,
			10, true, false, time.Now(), time.Now(), nil,
			"Global", "",
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{
			"registry":  "registry.terraform.io",
			"namespace": "hashicorp",
			"provider":  "aws",
		})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["allowed"] != false {
		t.Errorf("allowed = %v, want false", resp["allowed"])
	}
	reason, _ := resp["reason"].(string)
	if reason != "Denied by policy: deny-all" {
		t.Errorf("reason = %q, want %q", reason, "Denied by policy: deny-all")
	}
}

func TestRBACEvaluatePolicy_InactivePolicySkipped(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(sqlmock.NewRows(mpListCols).AddRow(
			knownUUID, nil, "inactive-allow", nil, "allow",
			nil, nil, nil,
			10, false, false, time.Now(), time.Now(), nil,
			"Global", "",
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{
			"registry":  "registry.terraform.io",
			"namespace": "hashicorp",
			"provider":  "aws",
		})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["allowed"] != false {
		t.Errorf("allowed = %v, want false (inactive policy should be skipped)", resp["allowed"])
	}
}

func TestRBACEvaluatePolicy_RequiresApproval(t *testing.T) {
	mock, r := newRBACRouter(t)
	mock.ExpectQuery("SELECT.*FROM mirror_policies.*WHERE mp.organization_id IS NULL").
		WillReturnRows(sqlmock.NewRows(mpListCols).AddRow(
			knownUUID, nil, "approval-required", nil, "allow",
			nil, nil, nil,
			10, true, true, time.Now(), time.Now(), nil,
			"Global", "",
		))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/policies/evaluate",
		jsonBody(map[string]interface{}{
			"registry":  "registry.terraform.io",
			"namespace": "hashicorp",
			"provider":  "aws",
		})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	resp := getJSON(w)
	if resp["allowed"] != true {
		t.Errorf("allowed = %v, want true", resp["allowed"])
	}
	if resp["requires_approval"] != true {
		t.Errorf("requires_approval = %v, want true", resp["requires_approval"])
	}
}

// UpdateRoleTemplate must report a failed sweep, exactly as DeleteRoleTemplate,
// RemoveMemberHandler and DeleteOrganizationHandler do. Narrowing a template's
// scopes and getting a clean 200 while the affected members' API keys are still
// live is the silent failure this whole change exists to stop reporting as
// success: the edit landed, the credentials carrying the old authority did not
// go away, and the admin had no way to know.
func TestRBACUpdateRoleTemplate_SweepFails_ReportsRevocationIncomplete(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow()) // scopes = ["modules:read","providers:write"]
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))
	// The member lookup that drives the sweep fails after the edit committed.
	mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_member_roles").
		WillReturnError(errDB)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			"scopes":       []string{"modules:read"}, // strictly narrower
		})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the edit itself succeeded): body=%s", w.Code, w.Body.String())
	}
	var body struct {
		DisplayName          string `json:"display_name"`
		RevocationIncomplete bool   `json:"revocation_incomplete"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body: %v: body=%s", err, w.Body.String())
	}
	if !body.RevocationIncomplete {
		t.Errorf("expected revocation_incomplete=true after a failed sweep, got body=%s", w.Body.String())
	}
	// The template itself is still the response body — the flag is additive.
	if body.DisplayName != "Reader Updated" {
		t.Errorf("display_name = %q, want %q: the success body must not change shape", body.DisplayName, "Reader Updated")
	}
}

// The happy path must NOT carry the flag, or it means nothing.
func TestRBACUpdateRoleTemplate_SweepSucceeds_NoRevocationIncomplete(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectExec("UPDATE role_templates.*SET display_name").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_member_roles").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "organization_id"}).
			AddRow("member-1", "org-1"))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs("member-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	expectOrgKeySweepScoped(mock, "member-1", "org-1", "key-rt-ok",
		[]byte(`["providers:write"]`))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
		jsonBody(map[string]interface{}{
			"name":         "reader",
			"display_name": "Reader Updated",
			"scopes":       []string{"modules:read"},
		})))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("revocation_incomplete")) {
		t.Errorf("a successful sweep must not report revocation_incomplete: body=%s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("revocation sweep was not issued: %v", err)
	}
}

// DeleteRoleTemplate reported revocation_incomplete only when the member
// LOOKUP failed. A lookup that succeeds followed by a sweep that fails leaves
// the caller in exactly the same state -- template gone, credentials live --
// and must report the same way.
func TestRBACDeleteRoleTemplate_SweepFails_ReportsRevocationIncomplete(t *testing.T) {
	mock, r := newRBACRouterWithRevocation(t, true)
	mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
		WillReturnRows(sampleRTRow())
	mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_member_roles").
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "organization_id"}).
			AddRow("member-1", "org-1"))
	mock.ExpectExec("DELETE FROM role_templates WHERE id").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WillReturnError(errDB)
	expectOrgKeySweep(mock, "member-1", "org-1", "key-rt-del-incomplete")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the delete itself succeeded): body=%s", w.Code, w.Body.String())
	}
	var body struct {
		RevocationIncomplete bool `json:"revocation_incomplete"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body: %v: body=%s", err, w.Body.String())
	}
	if !body.RevocationIncomplete {
		t.Errorf("expected revocation_incomplete=true after a failed sweep, got body=%s", w.Body.String())
	}
}
