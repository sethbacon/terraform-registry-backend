package admin

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// Tenant scoping for the /users family (identity #161).
//
// Every route in the family is gated on the FLAT users:read / users:write
// scope, and both are granted by the per-organization user_manager and
// org_owner role templates before being unioned org-lessly into the JWT (#652).
// The handlers then passed OrgScopeAllOrganizations(), so a role holder in one
// organization read and wrote users whose only memberships were elsewhere. On
// GET /users/:id the disclosed field was the organization list itself.
//
// These tests are table-driven over the PRINCIPAL, not over the route, because
// the defect was one decision (which tenancy to hand the accessor) reached from
// every route. Asserting only the reported route would leave its siblings
// unguarded and reporting green.
//
// They assert against userAxisScope directly rather than through sqlmock for
// the scope shape, because sqlmock matches query text and arguments but does
// not evaluate the predicate — a test that only checked "the query still ran"
// would pass with the guard removed. The end-to-end cases below then confirm
// the scope actually reaches the accessor, by asserting the 404 that an
// out-of-scope target produces.

// userScopeCtx builds a gin context carrying the given principal, plus the
// mock database the organization repository will resolve memberships against.
func userScopeCtx(t *testing.T, scopes []string, userID string) (*gin.Context, sqlmock.Sqlmock, *sql.DB) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/users/target", nil)
	if scopes != nil {
		c.Set("scopes", scopes)
	}
	if userID != "" {
		c.Set("user_id", userID)
	}
	return c, mock, db
}

// membershipRow is one GetUserMemberships row granting `scopes` in `orgID`.
func membershipRow(orgID string, scopes []string) *sqlmock.Rows {
	raw, _ := json.Marshal(scopes)
	return sqlmock.NewRows(membershipCols).
		AddRow(orgID, "org-"+orgID[:4], "role-1", time.Now(), "user_manager", "User Manager", raw)
}

// expectMembershipRowRegistryRole queues the read of registry's own role tables
// that now follows a membershipRow, answering with the SAME role and the SAME
// scopes so the resolved tenant scope is exactly what the row above granted.
func expectMembershipRowRegistryRole(mock sqlmock.Sqlmock, orgID string, scopes []string) {
	raw, _ := json.Marshal(scopes)
	expectRegistryRolesForUser(mock, registryRole{
		orgID: orgID, id: "role-1", name: "user_manager", displayName: "User Manager",
		scopes: string(raw),
	})
}

func TestUserAxisScope_ByPrincipal(t *testing.T) {
	tests := []struct {
		name string
		// principal
		scopes []string
		userID string
		// membership rows OrgScopeForUser will read (nil = no query expected)
		rows *sqlmock.Rows
		// the scopes those rows carry. Registry's own role tables are read
		// straight after and must answer with the same set, or the resolved
		// scope stops being the one the row above describes.
		roleScopes []string
		// expectations
		wantAll          bool
		wantPermitsAlpha bool
		wantPermitsBeta  bool
		wantUnowned      bool
	}{
		{
			name:             "platform admin keeps the whole directory",
			scopes:           []string{string(auth.ScopeAdmin)},
			userID:           scopeUserID,
			wantAll:          true,
			wantPermitsAlpha: true,
			wantPermitsBeta:  true,
			wantUnowned:      true,
		},
		{
			name:             "users:read in alpha only reaches alpha",
			scopes:           []string{string(auth.ScopeUsersRead)},
			userID:           scopeUserID,
			rows:             membershipRow(orgAlpha, []string{string(auth.ScopeUsersRead)}),
			roleScopes:       []string{string(auth.ScopeUsersRead)},
			wantPermitsAlpha: true,
			wantPermitsBeta:  false,
			wantUnowned:      true,
		},
		{
			name:   "membership without the required scope grants nothing",
			scopes: []string{string(auth.ScopeUsersRead)},
			userID: scopeUserID,
			// A member of alpha, but the role template there does not carry
			// users:read. Membership is not authority (#719).
			rows:             membershipRow(orgAlpha, []string{string(auth.ScopeModulesRead)}),
			roleScopes:       []string{string(auth.ScopeModulesRead)},
			wantPermitsAlpha: false,
			wantPermitsBeta:  false,
			wantUnowned:      true,
		},
		{
			name:             "no principal at all reaches no organization",
			wantPermitsAlpha: false,
			wantPermitsBeta:  false,
			wantUnowned:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, mock, db := userScopeCtx(t, tt.scopes, tt.userID)
			if tt.rows != nil {
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(tt.rows)
				expectMembershipRowRegistryRole(mock, orgAlpha, tt.roleScopes)
			}
			h := NewUserHandlers(&config.Config{}, db)

			scope, ok := userAxisScope(c, h.orgRepo, auth.ScopeUsersRead)
			if !ok {
				t.Fatal("userAxisScope reported failure")
			}
			if got := scope.IsAllOrganizations(); got != tt.wantAll {
				t.Errorf("IsAllOrganizations = %v, want %v (scope=%s)", got, tt.wantAll, scope.String())
			}
			if got := scope.PermitsOrganization(orgAlpha); got != tt.wantPermitsAlpha {
				t.Errorf("PermitsOrganization(alpha) = %v, want %v (scope=%s)", got, tt.wantPermitsAlpha, scope.String())
			}
			if got := scope.PermitsOrganization(orgBeta); got != tt.wantPermitsBeta {
				t.Errorf("PermitsOrganization(beta) = %v, want %v (scope=%s)", got, tt.wantPermitsBeta, scope.String())
			}
			// A membership-less user has no tenant boundary to cross, and
			// POST /users creates exactly that, so the creator must still be
			// able to read them back. This is the one deliberate widening.
			if got := scope.IncludesUnowned(); got != tt.wantUnowned {
				t.Errorf("IncludesUnowned = %v, want %v (scope=%s)", got, tt.wantUnowned, scope.String())
			}
		})
	}
}

// TestUserAxisScope_IsNotAllOrganizations is the mutation guard. Reverting the
// handlers to OrgScopeAllOrganizations() would leave every test above that
// exercises a non-admin passing only if this distinction is asserted, so it is
// asserted on its own: a scoped caller must NOT resolve to the whole directory.
func TestUserAxisScope_ScopedCallerIsNotPlatformWide(t *testing.T) {
	c, mock, db := userScopeCtx(t, []string{string(auth.ScopeUsersRead)}, scopeUserID)
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(membershipRow(orgAlpha, []string{string(auth.ScopeUsersRead)}))
	expectMembershipRowRegistryRole(mock, orgAlpha, []string{string(auth.ScopeUsersRead)})
	h := NewUserHandlers(&config.Config{}, db)

	scope, ok := userAxisScope(c, h.orgRepo, auth.ScopeUsersRead)
	if !ok {
		t.Fatal("userAxisScope reported failure")
	}
	if scope.IsAllOrganizations() {
		t.Fatal("a users:read holder in one organization resolved to the whole directory — the #161 defect")
	}
	if !scope.PermitsOrganization(orgAlpha) {
		t.Error("the caller's own organization must remain reachable")
	}
}

// --- end to end: the scope reaches the accessor -----------------------------

// scopedUserRouter wires the /users routes behind a non-admin users:read
// principal holding that scope in alpha only.
func scopedUserRouter(t *testing.T) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewUserHandlers(&config.Config{}, db)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeUsersRead)})
		c.Set("user_id", scopeUserID)
	})
	r.GET("/users/:id", h.GetUserHandler())
	r.GET("/users/:id/memberships", h.GetUserMembershipsHandler())
	return mock, r
}

// A target the scope does not reach is 404, not 403: on this route the
// organization list IS the disclosed field, so "exists, but not yours" would
// leak the membership the scope exists to withhold.
func TestGetUser_OutOfScopeTarget_Is404(t *testing.T) {
	mock, r := scopedUserRouter(t)
	// OrgScopeForUser: caller holds users:read in alpha.
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(membershipRow(orgAlpha, []string{string(auth.ScopeUsersRead)}))
	expectMembershipRowRegistryRole(mock, orgAlpha, []string{string(auth.ScopeUsersRead)})
	// Match the SCOPED form of the query specifically. sqlmock does not
	// evaluate predicates, so an expectation that merely said "FROM" would be
	// satisfied by the unscoped query too and this test would pass with the
	// guard reverted. OrgScope.membershipSQL emits this EXISTS ... = ANY($n)
	// clause only when the scope names organizations; a platform-wide scope
	// emits the literal TRUE and will not match here.
	mock.ExpectQuery("(?s)osm.organization_id = ANY").WillReturnRows(emptyUserRows())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/target", nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an out-of-scope user: body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "" && json.Valid([]byte(body)) {
		var m map[string]interface{}
		_ = json.Unmarshal([]byte(body), &m)
		// The response must not name the organizations it withheld.
		if _, leaked := m["organizations"]; leaked {
			t.Error("404 response carried an organizations field")
		}
	}
}

// GetUserMemberships has no scope parameter in the shared module, so the
// handler filters in Go. Assert the filter, since nothing in the query does it.
func TestGetUserMemberships_FiltersOutOfScopeOrganizations(t *testing.T) {
	mock, r := scopedUserRouter(t)
	mock.ExpectQuery("(?s)FROM organization_members").
		WillReturnRows(membershipRow(orgAlpha, []string{string(auth.ScopeUsersRead)}))
	expectMembershipRowRegistryRole(mock, orgAlpha, []string{string(auth.ScopeUsersRead)})
	// Scoped form, for the same reason as above.
	mock.ExpectQuery("(?s)osm.organization_id = ANY").WillReturnRows(sampleUserRow())
	// The target belongs to BOTH organizations; only alpha may be disclosed.
	both := sqlmock.NewRows(membershipCols).
		AddRow(orgAlpha, "org-alpha", "role-1", time.Now(), "viewer", "Viewer", []byte(`[]`)).
		AddRow(orgBeta, "org-beta", "role-2", time.Now(), "viewer", "Viewer", []byte(`[]`))
	mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(both)
	expectRegistryRolesForUser(mock,
		registryRole{orgID: orgAlpha, id: "role-1", name: "viewer", displayName: "Viewer", scopes: `[]`},
		registryRole{orgID: orgBeta, id: "role-2", name: "viewer", displayName: "Viewer", scopes: `[]`},
	)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/users/target/memberships", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); strings.Contains(body, orgBeta) {
		t.Errorf("response disclosed a membership in an organization the caller cannot reach: %s", body)
	}
	if body := w.Body.String(); !strings.Contains(body, orgAlpha) {
		t.Errorf("response dropped the membership the caller IS entitled to see: %s", body)
	}
}
