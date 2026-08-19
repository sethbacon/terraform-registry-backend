// identity_notfound_class_test.go pins the HTTP-level contract for every shape
// of "the identity store matched no row".
//
// As of terraform-suite-identity v0.24.0 a read that misses returns an error
// wrapping store.ErrNotFound instead of (nil, nil), and a by-identifier
// UPDATE/DELETE that matches zero rows does the same instead of reporting
// success. NEITHER change alters a signature, so every affected call site in
// this package still COMPILES and would silently change behaviour:
//
//   - a handler written `if err != nil { 500 }` then `if x == nil { 404 }`
//     keeps building and turns every 404 into a 500;
//   - an existence probe (is this email free? is this name taken?) becomes an
//     unconditional 500, because not-found is its SUCCESS case;
//   - an authorization check whose deny branch tested `member == nil` starts
//     answering 500 where it used to answer 403;
//   - a DELETE that was idempotent starts failing on its second call.
//
// The build cannot catch any of that, so these tests are the forcing function.
// Each one asserts the STATUS CODE, because the status is the contract a client
// depends on — asserting "no error" would pass for a 500 just as happily as for
// the 404 the endpoint is supposed to produce.
package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// nowT is a fixed-ish timestamp for mocked RETURNING clauses.
func nowT() time.Time { return time.Now() }

// ---------------------------------------------------------------------------
// Category 1 — by-id reads: a missing resource is 404, never 500
// ---------------------------------------------------------------------------

func TestNotFoundClass_GetUser_MissingIs404(t *testing.T) {
	mock, r := newUserRouter(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").WillReturnRows(emptyUserRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/nope", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (a missing user is not a server fault): body=%s",
			w.Code, w.Body.String())
	}
}

func TestNotFoundClass_GetUserMemberships_MissingUserIs404(t *testing.T) {
	mock, r := newUserRouter(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").WillReturnRows(emptyUserRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/nope/memberships", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestNotFoundClass_GetOrganization_MissingIs404(t *testing.T) {
	mock, r := newOrgRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").WillReturnRows(emptyOrgRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/nope", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestNotFoundClass_ListMembers_MissingOrgIs404(t *testing.T) {
	mock, r := newOrgRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").WillReturnRows(emptyOrgRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/organizations/nope/members", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

func TestNotFoundClass_GetAPIKey_MissingIs404(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", []string{"admin"})
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sqlmock.NewRows(akCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/apikeys/nope", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Category 2 — existence probes: not-found is the HAPPY path
//
// These are the sites most likely to be broken invisibly, because the miss is
// what SUCCESS looks like. A regression here does not produce a wrong 404; it
// produces a 500 on the ordinary, correct request.
// ---------------------------------------------------------------------------

func TestNotFoundClass_CreateUser_FreeEmailSucceeds(t *testing.T) {
	mock, r := newUserRouter(t)
	// No existing user with this address — the probe MISSES, which means the
	// address is available and creation must proceed.
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").WillReturnRows(emptyUserRows())
	mock.ExpectExec("INSERT INTO users").WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/users",
		jsonBody(map[string]string{"email": "free@example.com", "name": "Free"})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (a free email address must not fail the create): body=%s",
			w.Code, w.Body.String())
	}
}

func TestNotFoundClass_CreateOrganization_FreeNameSucceeds(t *testing.T) {
	mock, r := newOrgRouter(t)
	// GetByName misses -> the name is free.
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").WillReturnRows(emptyOrgRows())
	mock.ExpectQuery("INSERT INTO organizations").
		WillReturnRows(sqlmock.NewRows(orgCreateCols).AddRow("org-new", nowT(), nowT()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations",
		jsonBody(map[string]string{"name": "free-name", "display_name": "Free Name"})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (a free organization name must not fail the create): body=%s",
			w.Code, w.Body.String())
	}
}

// A taken name must still be rejected with 409 — the probe's OTHER outcome.
// Without this, "always treat the probe as free" would pass the test above.
func TestNotFoundClass_CreateOrganization_TakenNameIs409(t *testing.T) {
	mock, r := newOrgRouter(t)
	mock.ExpectQuery("SELECT.*FROM organizations WHERE name").
		WillReturnRows(sqlmock.NewRows(orgSQLCols).
			AddRow("org-1", "taken", "Taken", nil, nil, nowT(), nowT()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/organizations",
		jsonBody(map[string]string{"name": "taken", "display_name": "Taken"})))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (an existing name must still conflict): body=%s",
			w.Code, w.Body.String())
	}
}

func TestNotFoundClass_CreateUser_TakenEmailIs409(t *testing.T) {
	mock, r := newUserRouter(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").WillReturnRows(sampleUserRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/users",
		jsonBody(map[string]string{"email": "alice@example.com", "name": "Alice"})))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Category 3 — repeat DELETE keeps its documented success code
// ---------------------------------------------------------------------------

// DELETE /notifications/channels/:id is documented as 204 and has NO existence
// pre-check, so the second call reaches the repository and matches zero rows.
// It must stay idempotent: config-management loops re-apply the same desired
// state, and a 500 on "already absent" breaks every one of them.
func TestNotFoundClass_DeleteChannel_RepeatStays204(t *testing.T) {
	h, mock, _ := newChannelHandlers(t, nil)
	// Zero rows affected == the channel is already gone. Under v0.24.0 the
	// repository turns that into store.ErrNotFound.
	mock.ExpectExec("DELETE FROM notification_channels").
		WillReturnResult(sqlmock.NewResult(0, 0))

	c, _ := channelTestCtx(http.MethodDelete, "",
		gin.Params{{Key: "id", Value: "00000000-0000-0000-0000-000000000001"}})
	h.DeleteChannel(c)

	// DeleteChannel replies 204 with no body; assert on the gin writer, as
	// TestDeleteChannel does.
	if c.Writer.Status() != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (a repeat DELETE must stay idempotent)",
			c.Writer.Status())
	}
}

// DELETE /organizations/:id/members/:user_id returns 200 and likewise has no
// pre-check on the removal itself.
func TestNotFoundClass_RemoveMember_RepeatStays200(t *testing.T) {
	mock, r := newOrgRouter(t)
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(0, 0))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1/members/user-9", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (removing a non-member is already the desired state): body=%s",
			w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Category 4 — authorization denials stay denials
//
// The sharpest regression in the whole class: a deny branch that tested
// `member == nil` answers 500 once the miss becomes an error, which is still a
// refusal but reports a retryable server fault on a privilege boundary and
// makes a genuine database failure indistinguishable from a denial.
// ---------------------------------------------------------------------------

func TestNotFoundClass_CreateAPIKey_NonMemberIs403(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", []string{"apikeys:write"})
	// GetMemberWithRole misses -> the caller is not a member of the target org.
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sqlmock.NewRows(memberRoleCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys",
		jsonBody(map[string]any{
			"name":            "k",
			"organization_id": "org-1",
			"scopes":          []string{"modules:read"},
		})))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (non-member must be DENIED, not 500): body=%s",
			w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Category 5 — the audit log's non-probing property
//
// GetAuditLog carries the caller's scope INTO the query, so "no such entry" and
// "someone else's entry" are the same result by construction. Both must answer
// 404. Splitting them (404 vs 403) would rebuild the existence oracle the
// scoped query exists to deny.
// ---------------------------------------------------------------------------

func TestNotFoundClass_GetAuditLog_MissingIs404(t *testing.T) {
	mock, r := newAuditLogRouter(t)
	mock.ExpectQuery("SELECT.*FROM audit_logs").WillReturnRows(sqlmock.NewRows(auditLogGetCols))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/audit-logs/"+knownUUID, nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (out-of-scope and absent must be indistinguishable): body=%s",
			w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Category 6 — IdP reconciliation loops stay idempotent
//
// applyGroupMappings reconciles EVERY managed organization on every login, in
// one loop. Under v0.24.0 a RemoveMember or UpdateMemberRole that matches zero
// rows reports store.ErrNotFound, so a membership already in the desired state
// — a concurrent removal, or simply a second login racing the first — would
// abort the loop and fail the login, leaving every LATER organization
// unreconciled.
// ---------------------------------------------------------------------------

// The revoke branch: the membership this login wants to remove is already gone,
// and a SECOND managed organization still needs reconciling. The loop must
// reach it and the login must succeed.
func TestNotFoundClass_Reconcile_AlreadyRevokedDoesNotAbortLoop(t *testing.T) {
	db, mock, _ := newSQLMock()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "ops", Organization: "platform", Role: "operator"},
		{Group: "admins", Organization: "acme", Role: "editor"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	// platform: no matching group, currently a member -> revoke. The DELETE
	// matches ZERO rows: the membership is already gone.
	expectOrgByName(mock, "platform", "org-platform")
	expectIsMember(mock, "org-platform", "user-1", "rt-operator")
	mock.ExpectExec("DELETE FROM organization_members").
		WillReturnResult(sqlmock.NewResult(0, 0))

	// acme: the caller DOES hold this group, so it must still be reconciled.
	// If the loop aborted above, these expectations go unmet.
	expectOrgByName(mock, "acme", "org-acme")
	expectNotMember(mock)
	expectAddMember(mock, "editor", "rt-editor")

	if err := h.applyGroupMappings(context.Background(), "user-1", []string{"admins"}); err != nil {
		t.Fatalf("applyGroupMappings returned %v; an already-revoked membership is the desired state, not a failure", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the reconciliation loop did not reach every managed organization: %v", err)
	}
}

// The counterpart that keeps the test above honest: a REAL RemoveMember failure
// must still abort and surface. Without it, "ignore every RemoveMember error"
// would pass.
func TestNotFoundClass_Reconcile_RealRevokeFailureStillAborts(t *testing.T) {
	db, mock, _ := newSQLMock()
	defer db.Close()

	cfg := &config.Config{}
	cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
		{Group: "admins", Organization: "acme", Role: "editor"},
	}
	h, _ := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))

	expectOrgByName(mock, "acme", "org-acme")
	expectIsMember(mock, "org-acme", "user-1", "rt-editor")
	mock.ExpectExec("DELETE FROM organization_members").WillReturnError(errDB)

	if err := h.applyGroupMappings(context.Background(), "user-1", []string{"not-admins"}); err == nil {
		t.Error("expected a real RemoveMember failure to surface, got nil")
	}
}
