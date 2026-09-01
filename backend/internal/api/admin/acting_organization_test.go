package admin

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	idtenantscope "github.com/sethbacon/terraform-suite-identity/identity/tenantscope"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// withActingOrg sends the suite organization picker's header (issue #437).
func withActingOrg(req *http.Request, orgID string) *http.Request {
	req.Header.Set(idtenantscope.ActingOrganizationHeader, orgID)
	return req
}

// expectOrganizationByID primes the existence lookup resolveTargetOrganization
// makes on a platform admin's choice — the one check the shared module cannot
// make for a scope that spans every organization.
func expectOrganizationByID(mock sqlmock.Sqlmock, orgID string) {
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows(orgCols).
			AddRow(orgID, "acting-org", "Acting Org", nil, nil, time.Now(), time.Now()))
}

// expectOrganizationByIDMissing primes the same lookup to find no such
// organization.
func expectOrganizationByIDMissing(mock sqlmock.Sqlmock, orgID string) {
	mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
		WithArgs(orgID).
		WillReturnRows(sqlmock.NewRows(orgCols))
}

const (
	actingOrgA       = "aaaaaaaa-0437-4437-8437-aaaaaaaaaaaa"
	actingOrgB       = "bbbbbbbb-0437-4437-8437-bbbbbbbbbbbb"
	actingOrgForeign = "ffffffff-0437-4437-8437-ffffffffffff"
)

// actingOrgRoute mounts resolveTargetOrganization directly behind a principal,
// so the decision every CREATE in this package delegates to can be exercised
// without any handler's own statements in the way. The body's organization_id
// is passed through exactly as the handlers pass it.
func actingOrgRoute(db *sql.DB, principal gin.HandlerFunc) *gin.Engine {
	orgRepo := repositories.NewOrganizationRepository(db)
	r := gin.New()
	r.Use(principal)
	r.POST("/create", func(c *gin.Context) {
		var body struct {
			OrganizationID string `json:"organization_id"`
		}
		_ = c.ShouldBindJSON(&body)
		orgID, ok := resolveTargetOrganization(c, orgRepo, auth.ScopeMirrorsManage, body.OrganizationID)
		if !ok {
			return
		}
		c.JSON(http.StatusCreated, gin.H{"organization_id": orgID})
	})
	return r
}

// TestResolveTargetOrganization_ActingOrganization is the contract of issue
// #437 on the registry side: the organization a create lands in is the shared
// module's decision over the X-Organization-Id header, an explicit body field
// wins over the header, and whichever source named the organization is
// verified — never trusted.
func TestResolveTargetOrganization_ActingOrganization(t *testing.T) {
	const manage = `["mirrors:manage"]`
	member := createAxisCaller(string(auth.ScopeMirrorsManage))

	cases := []struct {
		name        string
		principal   gin.HandlerFunc
		memberships *createAxisMembershipFixture
		header      string
		body        string
		prime       func(sqlmock.Sqlmock)
		wantStatus  int
		wantOrg     string
		wantMessage string
	}{
		{
			name:        "single in-scope organization is used without naming it",
			principal:   member,
			memberships: createAxisMemberships(manage, actingOrgA),
			wantStatus:  http.StatusCreated,
			wantOrg:     actingOrgA,
		},
		{
			name:        "several in-scope organizations and nothing named is ambiguous, and the refusal names the header",
			principal:   member,
			memberships: createAxisMemberships(manage, actingOrgA, actingOrgB),
			wantStatus:  http.StatusBadRequest,
			wantMessage: idtenantscope.ActingOrganizationHeader,
		},
		{
			name:        "the header picks among the in-scope organizations",
			principal:   member,
			memberships: createAxisMemberships(manage, actingOrgA, actingOrgB),
			header:      actingOrgB,
			wantStatus:  http.StatusCreated,
			wantOrg:     actingOrgB,
		},
		{
			name:        "the header is trimmed",
			principal:   member,
			memberships: createAxisMemberships(manage, actingOrgA, actingOrgB),
			header:      "  " + actingOrgB + "\t",
			wantStatus:  http.StatusCreated,
			wantOrg:     actingOrgB,
		},
		{
			name:        "a header outside the scope is refused",
			principal:   member,
			memberships: createAxisMemberships(manage, actingOrgA, actingOrgB),
			header:      actingOrgForeign,
			wantStatus:  http.StatusForbidden,
			wantMessage: "Not a member of the requested organization",
		},
		{
			name:        "the body organization_id wins over the header",
			principal:   member,
			memberships: createAxisMemberships(manage, actingOrgA, actingOrgB),
			header:      actingOrgB,
			body:        actingOrgA,
			wantStatus:  http.StatusCreated,
			wantOrg:     actingOrgA,
		},
		{
			name:        "a body organization_id outside the scope is refused even when the header would pass",
			principal:   member,
			memberships: createAxisMemberships(manage, actingOrgA, actingOrgB),
			header:      actingOrgB,
			body:        actingOrgForeign,
			wantStatus:  http.StatusForbidden,
			wantMessage: "Not a member of the requested organization",
		},
		{
			name:        "no organization grants the required scope",
			principal:   member,
			memberships: createAxisMemberships(`["mirrors:read"]`, actingOrgA),
			header:      actingOrgA,
			wantStatus:  http.StatusForbidden,
			wantMessage: "Not a member of the requested organization",
		},
		{
			name:        "no organization at all and nothing named",
			principal:   member,
			memberships: createAxisMemberships(manage),
			wantStatus:  http.StatusForbidden,
			wantMessage: "No organization context",
		},
		{
			name:       "platform admin naming nothing is ambiguous — there is no default organization any more",
			principal:  createAxisAdmin(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "platform admin's header is verified to exist",
			principal:  createAxisAdmin(),
			header:     actingOrgB,
			prime:      func(m sqlmock.Sqlmock) { expectOrganizationByID(m, actingOrgB) },
			wantStatus: http.StatusCreated,
			wantOrg:    actingOrgB,
		},
		{
			name:        "platform admin naming an unknown organization gets the non-member's answer",
			principal:   createAxisAdmin(),
			header:      actingOrgForeign,
			prime:       func(m sqlmock.Sqlmock) { expectOrganizationByIDMissing(m, actingOrgForeign) },
			wantStatus:  http.StatusForbidden,
			wantMessage: "Not a member of the requested organization",
		},
		{
			name:      "platform admin's existence lookup failing is a 500, not a pass",
			principal: createAxisAdmin(),
			header:    actingOrgB,
			prime: func(m sqlmock.Sqlmock) {
				m.ExpectQuery("SELECT.*FROM organizations WHERE id").WillReturnError(errDB)
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })

			if tc.memberships != nil {
				mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(tc.memberships.rows)
				if len(tc.memberships.roles) > 0 {
					expectRegistryRolesForUser(mock, tc.memberships.roles...)
				}
			}
			if tc.prime != nil {
				tc.prime(mock)
			}

			body := "{}"
			if tc.body != "" {
				body = `{"organization_id":"` + tc.body + `"}`
			}
			req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tc.header != "" {
				req = withActingOrg(req, tc.header)
			}
			w := httptest.NewRecorder()
			actingOrgRoute(db, tc.principal).ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantOrg != "" && !strings.Contains(w.Body.String(), `"organization_id":"`+tc.wantOrg+`"`) {
				t.Errorf("resolved organization: body=%s, want %s", w.Body.String(), tc.wantOrg)
			}
			if tc.wantMessage != "" && !strings.Contains(w.Body.String(), tc.wantMessage) {
				t.Errorf("body=%s, want it to mention %q", w.Body.String(), tc.wantMessage)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("statements: %v", err)
			}
		})
	}
}
