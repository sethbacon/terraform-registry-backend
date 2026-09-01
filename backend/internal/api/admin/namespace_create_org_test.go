// namespace_create_org_test.go is the coverage of record for issue #778: a
// namespaced CREATE must write the new row into the organization the request
// was AUTHORIZED against, and into no other.
//
// The defect these rows pin is not "the request succeeded when it should have
// failed" — it succeeded either way. It is that the organization the route's
// publish guard checked and the organization the row landed in were two
// independent values, so a caller holding the scope in organization O created a
// row owned by the DEFAULT organization, which they need no membership in. A
// test that only asserted the status code passed throughout the entire lifetime
// of the bug. So every row here asserts the ORGANIZATION the handler addressed:
// the conflict lookup's predicate and the INSERT's organization_id are pinned
// with WithArgs, and the created row's organization_id is checked in the
// response body.
//
// The table is driven over both create paths — provider records and module
// records — because they are the same defect behind the same guard, and over
// both wiring states of that guard: owner_org_id published (every ordinary
// request) and owner_org_id absent (a platform admin passing through the
// ambiguous-ownership branch), which is the only path where the handler falls
// back to resolveTargetOrganization.
package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

const (
	// createOrgOwner is the organization that owns the namespace being
	// published into — the organization the publish guard authorized.
	createOrgOwner = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
	// createOrgOther is an organization the caller has nothing to do with.
	createOrgOther = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
	// createOrgDefault is the DEFAULT organization: the answer the defect
	// produced. Since #1011 no path asks for it at all — the platform-admin
	// fallback that did is gone — so it must never appear.
	createOrgDefault = "cccccccc-3333-4333-8333-cccccccccccc"

	createUserID = "dddddddd-4444-4444-8444-dddddddddddd"

	createNamespace = "hashicorp"
	createType      = "aws"
	createModName   = "vpc"
	createModSystem = "aws"
)

// setOwnerOrg stands in for middleware.NamespaceAuthorizer's publish guard,
// which resolves the namespace's owning organization and publishes it as
// owner_org_id before the handler runs. Mirroring only that one effect is the
// point: the handler must bind the row to the value the guard resolved, without
// re-deriving ownership from anything else.
func setOwnerOrg(orgID string) gin.HandlerFunc {
	return func(c *gin.Context) { c.Set("owner_org_id", orgID) }
}

// createAxisCaller installs an ordinary non-admin JWT principal.
func createAxisCaller(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("scopes", scopes)
		c.Set("user_id", createUserID)
	}
}

// createAxisAdmin installs a platform admin, whose scope spans every
// organization and who must therefore name the one a create lands in.
func createAxisAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("scopes", []string{string(auth.ScopeAdmin)})
		c.Set("user_id", createUserID)
	}
}

// createAxisMembershipFixture is a GetUserMemberships result together with the
// read of registry's own role tables that now follows it. They are built from
// the same scopes in one place so the membership and the role it confers cannot
// drift apart -- if they did, the resolver would see different authority than
// the row below describes and the case would silently stop testing what it says.
type createAxisMembershipFixture struct {
	rows  *sqlmock.Rows
	roles []registryRole
}

// createAxisMemberships builds a GetUserMemberships result granting `scopes` in
// each named organization.
func createAxisMemberships(scopes string, orgIDs ...string) *createAxisMembershipFixture {
	f := &createAxisMembershipFixture{rows: sqlmock.NewRows(membershipCols)}
	for i, id := range orgIDs {
		f.rows.AddRow(id, fmt.Sprintf("org-%d", i), "role-1", time.Now(),
			"devops", "DevOps", []byte(scopes))
		f.roles = append(f.roles, registryRole{
			orgID: id, id: "role-1", name: "devops", displayName: "DevOps", scopes: scopes,
		})
	}
	return f
}

// createAxisWant is the outcome required of ONE create path.
type createAxisWant struct {
	status int
	// org is the organization the handler must address: the predicate of the
	// conflict lookup and, when a row is written, the INSERT's
	// organization_id. Empty means the handler must refuse before touching the
	// resource table at all.
	org string
	// existing primes the conflict lookup with a row already present in `org`,
	// so no INSERT may follow. This is the half of the defect that is not about
	// authorization: the lookup ran against the wrong organization, so a
	// genuine collision in the authorized organization went unseen and the
	// insert met the UNIQUE (organization_id, namespace, ...) constraint
	// instead of returning cleanly.
	existing bool
}

type createAxisCase struct {
	name string
	// ownerOrg is what the route's publish guard published as owner_org_id.
	// Empty means the guard published nothing.
	ownerOrg  string
	principal gin.HandlerFunc
	// memberships is primed only when the fallback resolver is expected to
	// reach GetUserMemberships; a nil value asserts by omission that it does
	// not (an unexpected statement fails the row).
	memberships *createAxisMembershipFixture
	// membershipsErr makes the membership lookup fail.
	membershipsErr error
	// headerOrgID is the X-Organization-Id header the suite's organization
	// picker sends (#1011): a transport for the caller's choice, verified
	// exactly as a body organization_id is.
	headerOrgID string
	// wantOrgLookup primes the existence check resolveTargetOrganization makes
	// on a platform admin's choice — the one check the shared module cannot
	// make for a scope that spans every organization.
	wantOrgLookup string
	// wantOrgLookupMissing primes that lookup to find no such organization.
	wantOrgLookupMissing bool
	// bodyOrgID is the organization_id the caller puts in the request body.
	bodyOrgID string

	provider createAxisWant
	module   createAxisWant
}

func createAxisCases() []createAxisCase {
	const writeScopes = `["providers:write","modules:write"]`
	callerScopes := []string{string(auth.ScopeProvidersWrite), string(auth.ScopeModulesWrite)}

	return []createAxisCase{
		{
			// THE #778 ROW. Nothing is wrong with this request; the caller holds
			// the scope in the organization that owns the namespace and says so
			// by saying nothing. Before the fix the row was written into the
			// default organization anyway.
			name:      "guard authorized the owner, organization_id omitted",
			ownerOrg:  createOrgOwner,
			principal: createAxisCaller(callerScopes...),
			provider:  createAxisWant{status: http.StatusCreated, org: createOrgOwner},
			module:    createAxisWant{status: http.StatusCreated, org: createOrgOwner},
		},
		{
			name:      "guard authorized the owner, organization_id supplied and matching",
			ownerOrg:  createOrgOwner,
			principal: createAxisCaller(callerScopes...),
			bodyOrgID: createOrgOwner,
			provider:  createAxisWant{status: http.StatusCreated, org: createOrgOwner},
			module:    createAxisWant{status: http.StatusCreated, org: createOrgOwner},
		},
		{
			// THE IMPACT DISTINCTION between the two paths, encoded. The
			// provider request body has an organization_id field, so a caller
			// can name an organization other than the one the guard authorized;
			// that is refused. The module request body has no such field, so the
			// same key is inert there and the row still lands in the authorized
			// organization — a tenancy-BINDING gap, not a targetable
			// cross-tenant create.
			name:      "guard authorized the owner, organization_id names another organization",
			ownerOrg:  createOrgOwner,
			principal: createAxisCaller(callerScopes...),
			bodyOrgID: createOrgOther,
			provider:  createAxisWant{status: http.StatusForbidden},
			module:    createAxisWant{status: http.StatusCreated, org: createOrgOwner},
		},
		{
			// A platform admin crosses organization boundaries, but the row
			// still belongs to the namespace's owner: crossing the boundary is
			// permission to act, not licence to mis-attribute the row. Note what
			// is NOT primed — no GetDefaultOrganization lookup.
			name:      "platform admin, guard authorized the owner, organization_id omitted",
			ownerOrg:  createOrgOwner,
			principal: createAxisAdmin(),
			provider:  createAxisWant{status: http.StatusCreated, org: createOrgOwner},
			module:    createAxisWant{status: http.StatusCreated, org: createOrgOwner},
		},
		{
			// Admins are refused the mismatch too. The middleware exempts them
			// from its own organization_id/owner check, so this is the only
			// place the disagreement is caught, and silently overriding the
			// field would answer 201 to a write that discarded what was asked
			// for.
			name:      "platform admin, organization_id disagrees with the authorized owner",
			ownerOrg:  createOrgOwner,
			principal: createAxisAdmin(),
			bodyOrgID: createOrgOther,
			provider:  createAxisWant{status: http.StatusForbidden},
			module:    createAxisWant{status: http.StatusCreated, org: createOrgOwner},
		},
		{
			// THE CONFLICT-CHECK HALF. An existing row in the authorized
			// organization must be seen. Before the fix the lookup carried the
			// default organization's id, so this collision was invisible.
			name:      "existing row in the authorized organization is detected",
			ownerOrg:  createOrgOwner,
			principal: createAxisCaller(callerScopes...),
			provider:  createAxisWant{status: http.StatusConflict, org: createOrgOwner, existing: true},
			// The module create path answers 200 with the existing row rather
			// than 409; either way the lookup must address the authorized
			// organization.
			module: createAxisWant{status: http.StatusOK, org: createOrgOwner, existing: true},
		},

		// ------------------------------------------------------------------
		// FALLBACK WIRING: the guard published no owner. Reachable when a
		// platform admin passes through authorizeNamespaceMutation's
		// ambiguous-ownership branch, which returns without setting
		// owner_org_id. resolveTargetOrganization answers from the caller's own
		// tenancy here, and must never reach for the default organization on
		// behalf of a non-admin.
		// ------------------------------------------------------------------
		{
			name:        "no owner published, caller holds the scope in exactly one organization",
			principal:   createAxisCaller(callerScopes...),
			memberships: createAxisMemberships(writeScopes, createOrgOwner),
			provider:    createAxisWant{status: http.StatusCreated, org: createOrgOwner},
			module:      createAxisWant{status: http.StatusCreated, org: createOrgOwner},
		},
		{
			// Fail closed rather than guess. Guessing is how the default
			// organization became a dumping ground for other tenants' rows.
			name:        "no owner published, caller holds the scope in several organizations",
			principal:   createAxisCaller(callerScopes...),
			memberships: createAxisMemberships(writeScopes, createOrgOwner, createOrgOther),
			provider:    createAxisWant{status: http.StatusBadRequest},
			module:      createAxisWant{status: http.StatusBadRequest},
		},
		{
			name:        "no owner published, organization_id supplied and permitted",
			principal:   createAxisCaller(callerScopes...),
			memberships: createAxisMemberships(writeScopes, createOrgOwner, createOrgOther),
			bodyOrgID:   createOrgOwner,
			provider:    createAxisWant{status: http.StatusCreated, org: createOrgOwner},
			// Inert on the module path, so this row is the ambiguous case there.
			module: createAxisWant{status: http.StatusBadRequest},
		},
		{
			name:        "no owner published, organization_id supplied and NOT permitted",
			principal:   createAxisCaller(callerScopes...),
			memberships: createAxisMemberships(writeScopes, createOrgOwner),
			bodyOrgID:   createOrgOther,
			provider:    createAxisWant{status: http.StatusForbidden},
			// Inert on the module path: the caller cannot aim the row, so it
			// lands in their single in-scope organization.
			module: createAxisWant{status: http.StatusCreated, org: createOrgOwner},
		},
		{
			// Membership without the scope is not authority — the role template
			// decides. A member of the owner organization whose role grants only
			// reads holds the scope nowhere, so there is no organization to
			// create in.
			name:        "no owner published, caller holds the scope in no organization",
			principal:   createAxisCaller(callerScopes...),
			memberships: createAxisMemberships(`["providers:read","modules:read"]`, createOrgOwner),
			provider:    createAxisWant{status: http.StatusForbidden},
			module:      createAxisWant{status: http.StatusForbidden},
		},
		{
			// THE #1011 ROW. No owner published (a platform admin passing
			// through the ambiguous-ownership branch) and nothing named: this
			// used to be the one path that reached for the DEFAULT
			// organization. There is no such fallback any more — the admin's
			// scope spans every organization, so a create that names none is
			// refused as ambiguous on both paths, with no statement issued.
			name:      "no owner published, platform admin names nothing",
			principal: createAxisAdmin(),
			provider:  createAxisWant{status: http.StatusBadRequest},
			module:    createAxisWant{status: http.StatusBadRequest},
		},
		{
			// The picker's header is how a platform admin names the
			// organization on the module path, whose body has no
			// organization_id field at all. The choice is verified to exist
			// and the row lands in it.
			name:          "no owner published, platform admin acts through the picker header",
			principal:     createAxisAdmin(),
			headerOrgID:   createOrgOther,
			wantOrgLookup: createOrgOther,
			provider:      createAxisWant{status: http.StatusCreated, org: createOrgOther},
			module:        createAxisWant{status: http.StatusCreated, org: createOrgOther},
		},
		{
			// A platform admin naming an organization that does not exist is
			// refused with the non-member's 403, so the response discloses
			// nothing about which ids exist.
			name:                 "no owner published, platform admin's header names an unknown organization",
			principal:            createAxisAdmin(),
			headerOrgID:          createOrgOther,
			wantOrgLookup:        createOrgOther,
			wantOrgLookupMissing: true,
			provider:             createAxisWant{status: http.StatusForbidden},
			module:               createAxisWant{status: http.StatusForbidden},
		},
		{
			// A member of two organizations picks one through the header. Same
			// verification as a body organization_id: it must be an
			// organization they hold the scope in.
			name:        "no owner published, multi-organization member picks through the header",
			principal:   createAxisCaller(callerScopes...),
			memberships: createAxisMemberships(writeScopes, createOrgOwner, createOrgOther),
			headerOrgID: createOrgOther,
			provider:    createAxisWant{status: http.StatusCreated, org: createOrgOther},
			module:      createAxisWant{status: http.StatusCreated, org: createOrgOther},
		},
		{
			// The body field is the more specific statement, so it wins over
			// the picker's standing selection — and it is verified, not
			// trusted. The module body has no organization_id field, so there
			// the header is the only statement and the row follows it.
			name:        "no owner published, body organization_id wins over the header",
			principal:   createAxisCaller(callerScopes...),
			memberships: createAxisMemberships(writeScopes, createOrgOwner, createOrgOther),
			headerOrgID: createOrgOther,
			bodyOrgID:   createOrgOwner,
			provider:    createAxisWant{status: http.StatusCreated, org: createOrgOwner},
			module:      createAxisWant{status: http.StatusCreated, org: createOrgOther},
		},
		{
			// A body naming an organization outside the caller's scope is
			// refused even though the header alone would have passed: the
			// body wins, and what wins is verified.
			name:        "no owner published, body organization_id outside the scope is refused despite a valid header",
			principal:   createAxisCaller(callerScopes...),
			memberships: createAxisMemberships(writeScopes, createOrgOwner),
			headerOrgID: createOrgOwner,
			bodyOrgID:   createOrgOther,
			provider:    createAxisWant{status: http.StatusForbidden},
			module:      createAxisWant{status: http.StatusCreated, org: createOrgOwner},
		},
		{
			// A membership lookup that fails must not degrade into "no
			// organization named, use the default one".
			name:           "no owner published, membership lookup fails",
			principal:      createAxisCaller(callerScopes...),
			membershipsErr: errDB,
			provider:       createAxisWant{status: http.StatusInternalServerError},
			module:         createAxisWant{status: http.StatusInternalServerError},
		},
	}
}

// primeResolution primes the statements the organization resolution itself
// issues, in order. Nothing is primed for the guarded rows: resolving from
// owner_org_id must cost no queries at all, and an unexpected statement fails
// the row.
func primeResolution(mock sqlmock.Sqlmock, tc createAxisCase) {
	if tc.ownerOrg != "" {
		return
	}
	switch {
	case tc.membershipsErr != nil:
		mock.ExpectQuery("(?s)FROM organization_members").WillReturnError(tc.membershipsErr)
	case tc.memberships != nil:
		mock.ExpectQuery("(?s)FROM organization_members").WillReturnRows(tc.memberships.rows)
		if len(tc.memberships.roles) > 0 {
			expectRegistryRolesForUser(mock, tc.memberships.roles...)
		}
	}
	if tc.wantOrgLookup != "" {
		if tc.wantOrgLookupMissing {
			expectOrganizationByIDMissing(mock, tc.wantOrgLookup)
		} else {
			expectOrganizationByID(mock, tc.wantOrgLookup)
		}
	}
}

func createAxisBody(extra map[string]string) *strings.Reader {
	pairs := make([]string, 0, len(extra))
	for k, v := range extra {
		pairs = append(pairs, fmt.Sprintf("%q:%q", k, v))
	}
	return strings.NewReader("{" + strings.Join(pairs, ",") + "}")
}

func createAxisRequest(t *testing.T, r *gin.Engine, path string, body *strings.Reader, headerOrgID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", "application/json")
	if headerOrgID != "" {
		req = withActingOrg(req, headerOrgID)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// assertCreateAxis checks the outcome AND the organization the row landed in.
// Status alone is what let this defect live: every ordinary request answered
// 201 both before and after the fix.
func assertCreateAxis(t *testing.T, w *httptest.ResponseRecorder, mock sqlmock.Sqlmock, want createAxisWant) {
	t.Helper()
	if w.Code != want.status {
		t.Fatalf("status = %d, want %d: body=%s", w.Code, want.status, w.Body.String())
	}
	if want.status == http.StatusCreated {
		if !strings.Contains(w.Body.String(), want.org) {
			t.Errorf("created row is not owned by the authorized organization %s: body=%s",
				want.org, w.Body.String())
		}
		if strings.Contains(w.Body.String(), createOrgDefault) {
			t.Errorf("created row leaked into the default organization: body=%s", w.Body.String())
		}
	}
	// The WithArgs expectations carry the real assertion: the lookup predicate
	// and the INSERT's organization_id. An unmet or unmatched expectation means
	// the handler addressed a different organization.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("organization the handler addressed does not match: %v", err)
	}
}

func TestCreateProviderRecord_BindsRowToAuthorizedOrganization(t *testing.T) {
	for _, tc := range createAxisCases() {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })

			primeResolution(mock, tc)
			if want := tc.provider; want.org != "" {
				lookup := mock.ExpectQuery("SELECT.*FROM providers").
					WithArgs(want.org, createNamespace, createType)
				if want.existing {
					lookup.WillReturnRows(sqlmock.NewRows(providerCols).AddRow(
						"prov-1", want.org, createNamespace, createType,
						nil, nil, nil, time.Now(), time.Now(), nil))
				} else {
					lookup.WillReturnRows(emptyProviderRow())
					mock.ExpectQuery("INSERT INTO providers").
						WithArgs(want.org, createNamespace, createType,
							sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
						WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
							AddRow("prov-new", time.Now(), time.Now()))
				}
			}

			h := NewProviderAdminHandlers(db, &mockStorage{}, &config.Config{})
			r := gin.New()
			r.Use(tc.principal)
			handlers := []gin.HandlerFunc{}
			if tc.ownerOrg != "" {
				handlers = append(handlers, setOwnerOrg(tc.ownerOrg))
			}
			handlers = append(handlers, h.CreateProviderRecord)
			r.POST("/admin/providers", handlers...)

			body := map[string]string{"namespace": createNamespace, "type": createType}
			if tc.bodyOrgID != "" {
				body["organization_id"] = tc.bodyOrgID
			}
			w := createAxisRequest(t, r, "/admin/providers", createAxisBody(body), tc.headerOrgID)
			assertCreateAxis(t, w, mock, tc.provider)
		})
	}
}

func TestCreateModuleRecord_BindsRowToAuthorizedOrganization(t *testing.T) {
	for _, tc := range createAxisCases() {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })

			primeResolution(mock, tc)
			if want := tc.module; want.org != "" {
				lookup := mock.ExpectQuery("SELECT.*FROM modules").
					WithArgs(want.org, createNamespace, createModName, createModSystem)
				if want.existing {
					lookup.WillReturnRows(sqlmock.NewRows(moduleCols).AddRow(
						"mod-1", want.org, createNamespace, createModName, createModSystem,
						nil, nil, nil, time.Now(), time.Now(), nil, false, nil, nil, nil))
				} else {
					lookup.WillReturnRows(emptyModuleRow())
					mock.ExpectQuery("INSERT INTO modules").
						WithArgs(want.org, createNamespace, createModName, createModSystem,
							sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
						WillReturnRows(sqlmock.NewRows(modCreateCols).
							AddRow("mod-new", time.Now(), time.Now()))
				}
			}

			h := NewModuleAdminHandlers(db, &mockStorage{}, &config.Config{})
			r := gin.New()
			r.Use(tc.principal)
			handlers := []gin.HandlerFunc{}
			if tc.ownerOrg != "" {
				handlers = append(handlers, setOwnerOrg(tc.ownerOrg))
			}
			handlers = append(handlers, h.CreateModuleRecord)
			r.POST("/admin/modules/create", handlers...)

			body := map[string]string{
				"namespace": createNamespace,
				"name":      createModName,
				"system":    createModSystem,
			}
			if tc.bodyOrgID != "" {
				body["organization_id"] = tc.bodyOrgID
			}
			w := createAxisRequest(t, r, "/admin/modules/create", createAxisBody(body), tc.headerOrgID)
			// The existing-module path answers 200 with the row it found, so the
			// organization assertion for it is the lookup predicate plus the
			// body, not a 201.
			if tc.module.status == http.StatusOK && tc.module.existing {
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), tc.module.org) {
					t.Errorf("existing row was looked up in the wrong organization: body=%s", w.Body.String())
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf("organization the handler addressed does not match: %v", err)
				}
				return
			}
			assertCreateAxis(t, w, mock, tc.module)
		})
	}
}
