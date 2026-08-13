package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// The behavioural half of issue #766 on the organization routes: the floor's
// refusal has to reach the caller as a specific status and a specific message,
// not as "not 200".
//
// The structural half is admin_floor_class_test.go, which is what generalises
// to the handler somebody adds next year. These are what pin the contract the
// frontend and every SCIM/IdP integration read.

const (
	floorAdminScopes  = `["admin"]`
	floorOwnerScopes  = `["organizations:write","modules:write"]`
	floorViewerScopes = `["modules:read","organizations:read"]`
)

// newFlooredOrgRouter wires the member routes with a real adminfloor.Guard over
// two mocked connections, in the same shape the router builds: the carrier and
// the lock on the registry connection, the membership tables on identity's.
func newFlooredOrgRouter(t *testing.T) (registry, identity sqlmock.Sqlmock, r *gin.Engine) {
	t.Helper()
	rdb, rmock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (registry): %v", err)
	}
	t.Cleanup(func() { rdb.Close() })
	idb, imock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (identity): %v", err)
	}
	t.Cleanup(func() { idb.Close() })

	h := NewOrganizationHandlers(&config.Config{}, idb, repositories.NewNamespaceClaimRepository(idb), nil).
		WithAdminFloor(adminfloor.New(rdb, idb))

	r = gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "caller-admin")
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
	})
	r.PUT("/organizations/:id/members/:user_id", h.UpdateMemberHandler())
	r.DELETE("/organizations/:id/members/:user_id", h.RemoveMemberHandler())
	r.DELETE("/organizations/:id", h.DeleteOrganizationHandler())
	return rmock, imock, r
}

func floorExpectLock(registry sqlmock.Sqlmock) {
	registry.ExpectBegin()
	registry.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
}

// expectAnotherPlatformAdmin used to queue invariant A's read for the
// invariant-B cases below, so that A did not refuse first and leave B
// unreached. It is gone with the read: from migration 000054 invariant A counts
// the platform_admins carrier alone, and a MEMBERSHIP change cannot reduce it,
// so A returns before touching a connection and every case below lands in B
// with no fixture at all. Queueing anything for A would now be an unmatched
// expectation, which is the ordered mock saying the same thing.

func expectOrganizationState(identity sqlmock.Sqlmock, members ...[2]string) {
	rows := sqlmock.NewRows([]string{"user_id", "scopes"})
	for _, m := range members {
		rows.AddRow(m[0], []byte(m[1]))
	}
	identity.ExpectQuery("WHERE om.organization_id").WillReturnRows(rows)
}

func decodeError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, w.Body.String())
	}
	msg, _ := body["error"].(string)
	return msg
}

// TestRemoveMemberHandler_RefusesStrandingTheOrganization.
func TestRemoveMemberHandler_RefusesStrandingTheOrganization(t *testing.T) {
	registry, identity, r := newFlooredOrgRouter(t)
	floorExpectLock(registry)
	expectOrganizationState(identity,
		[2]string{"owner-1", floorOwnerScopes},
		[2]string{"viewer-1", floorViewerScopes},
	)
	registry.ExpectRollback()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/organizations/org-1/members/owner-1", nil))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	if got := decodeError(t, w); got != ErrMsgLastOrganizationAdmin {
		t.Fatalf("error = %q, want %q", got, ErrMsgLastOrganizationAdmin)
	}
	// No DELETE was queued, so an ordered mock also proves the write never ran.
	if err := identity.ExpectationsWereMet(); err != nil {
		t.Errorf("the membership write must not be attempted: %v", err)
	}
}

// TestRemoveMemberHandler_AllowsEmptyingAnOrganization is the empty-organization
// decision at the route: the last MEMBER may go, because an organization with
// nobody in it is not stranded.
func TestRemoveMemberHandler_AllowsEmptyingAnOrganization(t *testing.T) {
	registry, identity, r := newFlooredOrgRouter(t)
	floorExpectLock(registry)
	expectOrganizationState(identity, [2]string{"owner-1", floorOwnerScopes})
	identity.ExpectExec("DELETE FROM organization_members").WillReturnResult(sqlmock.NewResult(0, 1))
	registry.ExpectRollback()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/organizations/org-1/members/owner-1", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — removing the last member empties the organization, "+
			"which is legitimate: %s", w.Code, w.Body.String())
	}
}

// TestRemoveMemberHandler_StaysIdempotentForANonMember. The endpoint's
// idempotence predates the floor and is relied on by every retry and every
// concurrent deprovision; a guard that turned the second DELETE into a 409
// would break them.
func TestRemoveMemberHandler_StaysIdempotentForANonMember(t *testing.T) {
	registry, identity, r := newFlooredOrgRouter(t)
	floorExpectLock(registry)
	expectOrganizationState(identity,
		[2]string{"owner-1", floorOwnerScopes},
		[2]string{"viewer-1", floorViewerScopes},
	)
	// Zero rows: the identity store reports ErrNotFound, which the handler
	// swallows.
	identity.ExpectExec("DELETE FROM organization_members").WillReturnResult(sqlmock.NewResult(0, 0))
	registry.ExpectRollback()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/organizations/org-1/members/never-a-member", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — removing a non-member is a no-op, not a floor "+
			"violation: %s", w.Code, w.Body.String())
	}
}

// TestUpdateMemberHandler_RefusesDemotingTheLastOrganizationAdmin.
func TestUpdateMemberHandler_RefusesDemotingTheLastOrganizationAdmin(t *testing.T) {
	registry, identity, r := newFlooredOrgRouter(t)

	// checkRoleAssignment runs first; the caller is a platform administrator so
	// the ceiling permits anything and no per-org lookup happens.
	identity.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(floorViewerScopes)))
	// Then the existing-member read.
	identity.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "role_template_id", "created_at"}).
			AddRow("org-1", "owner-1", "role-owner", time.Now()))

	floorExpectLock(registry)
	// The floor's own read of the replacement template, then invariant A, then B.
	identity.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(floorViewerScopes)))
	expectOrganizationState(identity,
		[2]string{"owner-1", floorOwnerScopes},
		[2]string{"viewer-1", floorViewerScopes},
	)
	registry.ExpectRollback()

	body := `{"role_template_id":"66666666-6666-6666-6666-666666666666"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/organizations/org-1/members/owner-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	if got := decodeError(t, w); got != ErrMsgLastOrganizationAdmin {
		t.Fatalf("error = %q, want %q", got, ErrMsgLastOrganizationAdmin)
	}
	if err := identity.ExpectationsWereMet(); err != nil {
		t.Errorf("the role update must not be attempted: %v", err)
	}
}

// TestUpdateMemberHandler_RefusesClearingTheLastOrganizationAdminsRole covers
// `{"role_template_id": null}`, which names no template at all and is the case
// a check keyed on "the new template's scopes" lets through.
func TestUpdateMemberHandler_RefusesClearingTheLastOrganizationAdminsRole(t *testing.T) {
	registry, identity, r := newFlooredOrgRouter(t)

	// checkRoleAssignment short-circuits on a nil template, so no read here.
	identity.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "role_template_id", "created_at"}).
			AddRow("org-1", "owner-1", "role-owner", time.Now()))

	floorExpectLock(registry)
	expectOrganizationState(identity,
		[2]string{"owner-1", floorOwnerScopes},
		[2]string{"viewer-1", floorViewerScopes},
	)
	registry.ExpectRollback()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/organizations/org-1/members/owner-1",
		bytes.NewBufferString(`{"role_template_id":null}`)))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	if got := decodeError(t, w); got != ErrMsgLastOrganizationAdmin {
		t.Fatalf("error = %q, want %q", got, ErrMsgLastOrganizationAdmin)
	}
}

// TestUpdateMemberHandler_AllowsReRolingOntoAnotherAdministrativeTemplate is
// the positive control: a sideways move that keeps organizations:write is not
// a demotion and must still work.
func TestUpdateMemberHandler_AllowsReRolingOntoAnotherAdministrativeTemplate(t *testing.T) {
	registry, identity, r := newFlooredOrgRouter(t)

	identity.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(floorOwnerScopes)))
	identity.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
		WillReturnRows(sqlmock.NewRows([]string{"organization_id", "user_id", "role_template_id", "created_at"}).
			AddRow("org-1", "owner-1", "role-owner", time.Now()))

	floorExpectLock(registry)
	identity.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(floorOwnerScopes)))
	expectOrganizationState(identity,
		[2]string{"owner-1", floorOwnerScopes},
		[2]string{"viewer-1", floorViewerScopes},
	)
	identity.ExpectExec("UPDATE organization_members").WillReturnResult(sqlmock.NewResult(0, 1))
	registry.ExpectRollback()
	// The response read-back.
	identity.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols).AddRow(
			"org-1", "owner-1", "role-owner-2", time.Now(),
			"Owner One", "owner@example.com", "org_owner", "Organization Owner",
			[]byte(floorOwnerScopes),
		))

	body := `{"role_template_id":"77777777-7777-7777-7777-777777777777"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/organizations/org-1/members/owner-1",
		bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — moving between two administrative templates is not a "+
			"reduction: %s", w.Code, w.Body.String())
	}
}

// TestDeleteOrganizationHandler_RefusesRemovingTheLastPlatformAdmin. The
// membership rows go by FK cascade, so there is no membership statement on this
// path for anything else to notice.
func TestDeleteOrganizationHandler_RefusesRemovingTheLastPlatformAdmin(t *testing.T) {
	registry, identity, r := newFlooredOrgRouter(t)

	// The handler's own pre-checks: organization exists, owns no namespace
	// claims, owns no artifacts.
	identity.ExpectQuery("SELECT.*FROM organizations WHERE id").WillReturnRows(sampleOrgRow())
	identity.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	identity.ExpectQuery("SELECT EXISTS.*FROM modules").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	floorExpectLock(registry)
	// Neither invariant-A read is queued. The carrier is the only source of
	// platform-admin authority from migration 000054, an organization deletion
	// does not touch it, and an ordered mock turns a floor that still consulted
	// either connection into a failure here.
	identity.ExpectExec("DELETE FROM organizations").WillReturnResult(sqlmock.NewResult(0, 1))
	registry.ExpectRollback()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/organizations/org-1", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — deleting an organization cannot remove a carrier grant, "+
			"so the floor has nothing to refuse: %s", w.Code, w.Body.String())
	}
	if err := identity.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet/unexpected expectations: %v", err)
	}
}

// TestRespondAdminFloor pins the status/message mapping every call site shares.
func TestRespondAdminFloor(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantHandle bool
		wantStatus int
		wantMsg    string
	}{
		{"nil", nil, false, 0, ""},
		{"platform floor", adminfloor.ErrLastPlatformAdmin, true, http.StatusConflict, ErrMsgLastPlatformAdmin},
		{"organization floor", adminfloor.ErrLastOrganizationAdmin, true, http.StatusConflict, ErrMsgLastOrganizationAdmin},
		{"indeterminate", adminfloor.ErrIndeterminate, true, http.StatusInternalServerError, ErrMsgFloorIndeterminate},
		{"unrelated", http.ErrNoCookie, false, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodDelete, "/", nil)

			if got := respondAdminFloor(c, tt.err); got != tt.wantHandle {
				t.Fatalf("handled = %v, want %v", got, tt.wantHandle)
			}
			if !tt.wantHandle {
				return
			}
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if got := decodeError(t, w); got != tt.wantMsg {
				t.Fatalf("error = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

// TestEraseUserHandler_RefusesStrandingTheDeployment.
//
// The GDPR erasure is the widest authority reduction in the product — an
// unscoped `DELETE FROM organization_members` plus an anonymised users row that
// can never log in again — and its handler used to map EVERY error onto 404
// with the raw error string. A floor refusal would have arrived as
// "404: adminfloor: the deployment would be left with no platform
// administrator": a refusal disguised as an absent resource, which a caller
// reconciles by giving up rather than by appointing somebody else.
func TestEraseUserHandler_RefusesStrandingTheDeployment(t *testing.T) {
	rdb, registry, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (registry): %v", err)
	}
	defer rdb.Close()
	idb, identity, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New (identity): %v", err)
	}
	defer idb.Close()

	svc := services.NewUserService(idb).
		WithAdminFloor(adminfloor.New(rdb, idb), repositories.NewPlatformAdminRepository(rdb), audit.NewOutbox(rdb))
	h := NewGDPRHandlers(svc)

	registry.ExpectBegin()
	registry.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	// The subject is the deployment's only carrier administrator, and erasing
	// them makes their own grant unexercisable — the one shape that can still
	// break invariant A now that authority is carrier-only (migration 000054).
	registry.ExpectQuery("FROM platform_admins").
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow("only-admin"))
	registry.ExpectRollback()

	r := gin.New()
	r.POST("/admin/users/:id/erase", h.EraseUserHandler())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/users/only-admin/erase", nil))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 — a floor refusal must not be served as 404: %s",
			w.Code, w.Body.String())
	}
	if got := decodeError(t, w); got != ErrMsgLastPlatformAdmin {
		t.Fatalf("error = %q, want %q", got, ErrMsgLastPlatformAdmin)
	}
	// No erasure statement was queued, so an ordered mock also proves the
	// transaction never opened on the identity connection.
	if err := identity.ExpectationsWereMet(); err != nil {
		t.Errorf("the erasure must not be attempted: %v", err)
	}
}
