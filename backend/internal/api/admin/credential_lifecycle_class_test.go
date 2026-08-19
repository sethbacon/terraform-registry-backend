package admin

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/terraform-registry/terraform-registry/internal/api/scim"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/credlifecycle"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// multipartPublishRequest builds the multipart POST a module publish uses, so
// the first-claim rows drive RequirePublishAccessFromForm the way a real
// publish does.
func multipartPublishRequest(t *testing.T, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%q): %v", k, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("multipart Close: %v", err)
	}
	req := httptest.NewRequest("POST", "/modules", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

// ---------------------------------------------------------------------------
// Class test: authority-reduction must invalidate every credential family
// (issues #732, #736)
// ---------------------------------------------------------------------------
//
// DEFECT CLASS
//
//	A handler commits an event that REDUCES a principal's derived authority
//	(organization membership removed, member's role template reassigned, role
//	template edited or deleted, user deprovisioned by the IdP) but does not
//	invalidate every credential that carries a *snapshot* of that authority.
//	The registry has two such families -- JWT sessions (scopes embedded at
//	login) and API keys (scopes AND organization_id stored on the api_keys row)
//	-- and before this test only the JWT family was swept, at only some events.
//	An offboarded member therefore kept a working modules:write/providers:write
//	credential into the organization's namespaces with no expiry at all.
//
// This table is the class, one row per enumerated site. Adding a new
// authority-reducing site without a row here is the regression the enumeration
// signature (backend/tools/credlifecycle) is there to catch; removing the
// guard from any single site must fail exactly that site's row.
//
// The last row is the complementary use-time control: even for a key some
// lifecycle path failed to sweep, the namespace authorizer re-verifies the
// key owner's current membership instead of trusting the key's frozen org
// binding, so a stale key fails closed.

// expectOrgKeySweep registers the two statements that revoke an API key userID
// holds in orgID: the org-scoped list, then the delete of the one key it
// returns. The key carries testKeyScopes, which no reduced authority in this
// file still grants, so it is always the delete case.
func expectOrgKeySweep(mock sqlmock.Sqlmock, userID, orgID, keyID string) {
	expectOrgKeySweepScoped(mock, userID, orgID, keyID, testKeyScopes)
}

// expectOrgKeySweepScoped is expectOrgKeySweep with the swept key's frozen
// scopes stated explicitly. The sweep only deletes keys asking for MORE than
// the principal retains, so a row whose reduction leaves testKeyScopes intact
// must name a scope the reduction actually removes.
func expectOrgKeySweepScoped(mock sqlmock.Sqlmock, userID, orgID, keyID string, scopes []byte) {
	expectOrgKeyList(mock, userID, orgID, keyID, scopes)
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs(keyID, sqlmock.AnyArg()). // + the OrgScope predicate's bound ids
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// expectOrgKeyList registers ONLY the org-scoped list, with no following
// delete: the caller is asserting that this key is RETAINED because every
// scope it carries is still granted after the change.
func expectOrgKeyList(mock sqlmock.Sqlmock, userID, orgID, keyID string, scopes []byte) {
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs(userID, orgID, sqlmock.AnyArg()). // + the OrgScope predicate's bound ids

		WillReturnRows(sqlmock.NewRows(akListCols).
			AddRow(keyID, userID, orgID, "CI Key", nil, "hashedkey", "tfr_abc123",
				scopes, nil, nil, nil, time.Now(), nil))
}

// expectAllKeysSweep registers the statement that revokes every API key userID
// holds in the swept organizations -- the whole-principal offboarding sweep.
//
// ONE scoped DELETE since identity v0.25.0, not a list followed by a revoke per
// key: the tenant predicate is in the statement, so the set of keys the sweep
// touches is decided by the database rather than by a filter the caller could
// forget to apply.
func expectAllKeysSweep(mock sqlmock.Sqlmock, userID, keyID string) {
	mock.ExpectExec("DELETE FROM api_keys WHERE user_id").
		WillReturnResult(sqlmock.NewResult(0, 1))
	_ = keyID // the sweep is set-based; no key is named at the call site any more
}

// scimUserRows is the row shape of identity UserRepository.GetUserByID.
func scimUserRows(userID string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "email", "name", "oidc_sub", "created_at", "updated_at"}).
		AddRow(userID, "jane@example.com", "Jane Doe", nil, time.Now(), time.Now())
}

// newSCIMDeprovisionRouter builds the real SCIM handler set with the credential
// sweeper wired over the mocked connection.
func newSCIMDeprovisionRouter(db *sql.DB) *gin.Engine {
	h := scim.NewHandlers(&config.Config{}, db, scim.WithCredentialSweeper(
		credlifecycle.NewSweeper(
			repositories.NewUserTokenRevocationRepository(db),
			repositories.NewAPIKeyRepository(db),
		),
	))
	r := gin.New()
	// Platform admin: these tests cover the CREDENTIAL half of deprovisioning
	// (issues #732/#736), not tenancy. Admin is the principal #719's SCIM
	// tenant-scope guard deliberately exempts -- an IdP integration wired with
	// an admin-scoped credential is the normal deployment -- so it is the one
	// that still takes the single-statement RemoveAllMembershipsForUser sweep
	// these expectations encode. Cross-tenant behaviour for the same handlers
	// is owned by scim/tenant_scope_class_test.go, which drives them as a
	// non-admin scim:provision holder.
	r.Use(func(c *gin.Context) { c.Set("scopes", []string{string(auth.ScopeAdmin)}) })
	r.PUT("/scim/v2/Users/:id", h.PutUser())
	r.PATCH("/scim/v2/Users/:id", h.PatchUser())
	r.DELETE("/scim/v2/Users/:id", h.DeleteUser())
	return r
}

// expectSCIMDeprovisionSweep registers the shared tail of every SCIM
// deprovisioning path: strip memberships, move the JWT watermark, revoke all
// API keys.
func expectSCIMDeprovisionSweep(mock sqlmock.Sqlmock, userID string) {
	// The strip is a QUERY now, not an Exec: it RETURNS the organizations whose
	// membership it actually removed, and that value — an OrgScope — is what
	// scopes the key sweep below. The two halves cannot disagree about tenancy
	// because the second's argument IS the first's result (identity #160/#736).
	mock.ExpectQuery("DELETE FROM organization_members").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"organization_id"}).AddRow(scimRemovedOrg))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	// GUARD scim-deprovision-sweep-inherits-strip-scope (identity #160). The
	// sweep must carry the organizations the strip ACTUALLY removed, not the
	// platform-wide scope: an organization where no membership was removed had
	// no authority reduced there and must keep its keys. A mutant passing
	// OrgScopeAllOrganizations() renders the predicate as the literal TRUE,
	// binds no array, and fails both halves of this expectation.
	mock.ExpectExec(`DELETE FROM api_keys WHERE user_id = \$1 AND organization_id = ANY\(\$2\)`).
		WithArgs(userID, boundOrgScope{want: []string{scimRemovedOrg}}).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// scimRemovedOrg is the single organization the SCIM strip reports as actually
// removed, and therefore the only one the paired credential sweep may reach.
const scimRemovedOrg = "org-scim-removed"

// boundOrgScope matches the array argument an OrgScope binds into a statement,
// asserting which organization ids it names and which it does not.
type boundOrgScope struct {
	want    []string
	notWant []string
}

func (b boundOrgScope) Match(v driver.Value) bool {
	s := fmt.Sprint(v)
	for _, w := range b.want {
		if !strings.Contains(s, w) {
			return false
		}
	}
	for _, n := range b.notWant {
		if strings.Contains(s, n) {
			return false
		}
	}
	return true
}

// A PUT that does not mention "active" must not deprovision anything.
//
// SCIMUser.Active was a plain bool, so an omitted attribute zero-valued to
// false and PutUser read that as "deactivate": a partial PUT from an IdP -- or
// any client updating only a display name -- silently stripped every
// organization membership and, once #736 wired the sweep in, irreversibly
// deleted every API key the user held in every organization. Asserted by
// registering ONLY the lookup and the update: sqlmock fails the test if the
// handler issues a membership delete, a watermark write, or any key statement.
func TestSCIMPutUser_OmittedActive_DoesNotDeprovision(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	logs := captureSlogOutput(t)
	r := newSCIMDeprovisionRouter(db)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WillReturnRows(scimUserRows("user-scim"))
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/scim/v2/Users/user-scim",
		bytes.NewBufferString(`{"userName":"jane@example.com","name":{"formatted":"Jane R Doe"}}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a PUT omitting \"active\" deprovisioned the user: %v", err)
	}
	// The decisive assertion. sqlmock cannot carry it alone: the membership
	// delete's error is discarded by design (`_ =`) and the sweep swallows its
	// own failures, so every extra statement a wrongly-triggered deprovision
	// issues would be absorbed and ExpectationsWereMet() would still pass.
	if strings.Contains(logs.String(), "scim: user deactivated via PUT") {
		t.Errorf("a PUT that never mentioned \"active\" deprovisioned the user; logs: %s", logs.String())
	}
}

// The explicit form still deprovisions -- the fix must not disable the
// feature, only require the IdP to actually say it. (The full sweep for this
// path is asserted as a row in the class table above; this is the paired
// negative/positive control for the pointer semantics.)
func TestSCIMPutUser_ExplicitActiveFalse_StillDeprovisions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := newSQLMock()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	r := newSCIMDeprovisionRouter(db)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
		WillReturnRows(scimUserRows("user-scim"))
	expectSCIMDeprovisionSweep(mock, "user-scim")
	mock.ExpectExec("UPDATE users").
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/scim/v2/Users/user-scim",
		bytes.NewBufferString(`{"userName":"jane@example.com","active":false}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an explicit active=false must still deprovision: %v", err)
	}
}

type credLifecycleCase struct {
	// site is the stable identity of the enumerated defect instance.
	site string
	// run wires the real handler over db, registers the SQL the sweep must
	// issue, and drives the lifecycle event.
	run func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock)
}

func TestCredentialLifecycleClass_AuthorityReductionInvalidatesAllCredentialFamilies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []credLifecycleCase{
		{
			// #732 primary instance.
			site: "admin.OrganizationHandlers.RemoveMemberHandler / DELETE /api/v1/organizations/:id/members/:user_id",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				h := NewOrganizationHandlers(&config.Config{}, db,
					repositories.NewNamespaceClaimRepository(db),
					repositories.NewUserTokenRevocationRepository(db))
				r := gin.New()
				r.DELETE("/organizations/:id/members/:user_id", h.RemoveMemberHandler())

				mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
					WillReturnRows(sampleMemberWithRoleRow())
				expectSampleMemberRegistryRole(mock)
				mock.ExpectExec("DELETE FROM organization_members").
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec("INSERT INTO user_token_revocations").
					WithArgs("user-1").
					WillReturnResult(sqlmock.NewResult(1, 1))
				expectOrgKeySweep(mock, "user-1", "org-1", "key-removed-member")

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1/members/user-1", nil))
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			site: "admin.OrganizationHandlers.UpdateMemberHandler / PUT /api/v1/organizations/:id/members/:user_id",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				h := NewOrganizationHandlers(&config.Config{}, db,
					repositories.NewNamespaceClaimRepository(db),
					repositories.NewUserTokenRevocationRepository(db))
				r := gin.New()
				r.PUT("/organizations/:id/members/:user_id", h.UpdateMemberHandler())

				mock.ExpectQuery("SELECT scopes FROM registry_role_templates WHERE id").
					WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(`[]`)))
				mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
					WillReturnRows(sampleOrgMemberRowWithRole(oldRoleTemplateUUID))
				expectRegistryRoleFor(mock, registryRole{id: oldRoleTemplateUUID})
				mock.ExpectExec("UPDATE organization_members").
					WillReturnResult(sqlmock.NewResult(1, 1))
				// The scopes the member RETAINS under the new role template
				// decide which keys over-ask. sampleMemberWithRoleRow carries
				// modules:read, so a key with providers:write is deleted.
				mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
					WillReturnRows(sampleMemberWithRoleRow())
				expectSampleMemberRegistryRole(mock)
				mock.ExpectExec("INSERT INTO user_token_revocations").
					WithArgs("user-1").
					WillReturnResult(sqlmock.NewResult(1, 1))
				expectOrgKeySweepScoped(mock, "user-1", "org-1", "key-rerole",
					[]byte(`["providers:write"]`))
				mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
					WillReturnRows(sampleMemberWithRoleRow())
				expectSampleMemberRegistryRole(mock)

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("PUT", "/organizations/org-1/members/user-1",
					bytes.NewBufferString(`{"role_template_id": "`+newRoleTemplateUUID+`"}`)))
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			site: "admin.RBACHandlers.UpdateRoleTemplate / PUT /api/v1/admin/role-templates/:id",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				h := NewRBACHandlers(
					repositories.NewRBACRepository(sqlx.NewDb(db, "sqlmock")),
					repositories.NewUserTokenRevocationRepository(db),
					repositories.NewAPIKeyRepository(db))
				r := gin.New()
				r.Use(func(c *gin.Context) { c.Set("user_id", knownUserUUID) })
				r.PUT("/role-templates/:id", h.UpdateRoleTemplate)

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
				// The key carries providers:write, which the narrowed template
				// no longer grants, so it over-asks and is deleted.
				expectOrgKeySweepScoped(mock, "member-1", "org-1", "key-rt-edit",
					[]byte(`["providers:write"]`))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("PUT", "/role-templates/"+knownUUID,
					jsonBody(map[string]interface{}{
						"name":         "reader",
						"display_name": "Reader Updated",
						"scopes":       []string{"modules:read"}, // narrower than testRTScopes
					})))
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			site: "admin.RBACHandlers.DeleteRoleTemplate / DELETE /api/v1/admin/role-templates/:id",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				h := NewRBACHandlers(
					repositories.NewRBACRepository(sqlx.NewDb(db, "sqlmock")),
					repositories.NewUserTokenRevocationRepository(db),
					repositories.NewAPIKeyRepository(db))
				r := gin.New()
				r.Use(func(c *gin.Context) { c.Set("user_id", knownUserUUID) })
				r.DELETE("/role-templates/:id", h.DeleteRoleTemplate)

				mock.ExpectQuery("SELECT.*FROM registry_role_templates WHERE id").
					WillReturnRows(sampleRTRow())
				mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_member_roles").
					WillReturnRows(sqlmock.NewRows([]string{"user_id", "organization_id"}).
						AddRow("member-1", "org-1"))
				mock.ExpectExec("DELETE FROM role_templates WHERE id").
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec("INSERT INTO user_token_revocations").
					WithArgs("member-1").
					WillReturnResult(sqlmock.NewResult(1, 1))
				expectOrgKeySweep(mock, "member-1", "org-1", "key-rt-delete")

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("DELETE", "/role-templates/"+knownUUID, nil))
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			// IdP-driven deprovisioning at login: the group that granted the org
			// is gone, so the membership is removed. Only the API-key family is
			// swept here on purpose -- see credlifecycle.Sweeper.OrgKeysOnly.
			site: "admin.AuthHandlers.reconcileGroupMemberships (IdP deprovision branch, OIDC/SAML/LDAP login)",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				cfg := &config.Config{}
				cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
					{Group: "platform-team", Organization: "acme", Role: "editor"},
				}
				h, err := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour),
					WithCredentialSweeper(credlifecycle.NewSweeper(
						repositories.NewUserTokenRevocationRepository(db),
						repositories.NewAPIKeyRepository(db))))
				if err != nil {
					t.Fatalf("NewAuthHandlers: %v", err)
				}

				mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
					WithArgs("acme").
					WillReturnRows(sqlmock.NewRows(authOrgCols).
						AddRow("org-1", "acme", "Acme Corp", nil, nil, time.Now(), time.Now()))
				roleID := "rt-old"
				mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
					WillReturnRows(sqlmock.NewRows(authMemberCols).
						AddRow("org-1", "user-1", &roleID, time.Now()))
				expectRegistryRoleFor(mock, registryRole{id: roleID})
				mock.ExpectExec("DELETE FROM organization_members").
					WillReturnResult(sqlmock.NewResult(0, 1))
				expectOrgKeySweep(mock, "user-1", "org-1", "key-idp-deprovision")

				// Login no longer carries "platform-team" → deprovision branch.
				if err := h.applyGroupMappings(context.Background(), "user-1", []string{"other-team"}); err != nil {
					t.Fatalf("applyGroupMappings: %v", err)
				}
			},
		},
		{
			// The OTHER reducing arm of the same switch as the row above, and
			// the one the fix originally missed. An IdP group change can map a
			// user to a LOWER role (owner -> viewer); that arm commits the
			// reduction through UpdateMemberRole and swept nothing, while its
			// sibling swept the org's keys. Because the enclosing function
			// reached both credential families through the sibling, neither the
			// class table nor the enumeration signature scored it as a gap --
			// which is why the signature now asks the question per branch.
			site: "admin.AuthHandlers.reconcileGroupMemberships (IdP role-reassignment branch, demotion)",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				cfg := &config.Config{}
				cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
					{Group: "platform-team", Organization: "acme", Role: "viewer"},
				}
				h, err := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour),
					WithCredentialSweeper(credlifecycle.NewSweeper(
						repositories.NewUserTokenRevocationRepository(db),
						repositories.NewAPIKeyRepository(db))))
				if err != nil {
					t.Fatalf("NewAuthHandlers: %v", err)
				}

				mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
					WithArgs("acme").
					WillReturnRows(sqlmock.NewRows(authOrgCols).
						AddRow("org-1", "acme", "Acme Corp", nil, nil, time.Now(), time.Now()))
				// Already a member, under the template they are about to lose.
				oldRole := "rt-owner"
				mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
					WillReturnRows(sqlmock.NewRows(authMemberCols).
						AddRow("org-1", "user-1", &oldRole, time.Now()))
				expectRegistryRoleFor(mock, registryRole{id: oldRole})
				// The guard's lookup doubles as the retention filter: "viewer"
				// grants read only, so it is what the member retains.
				expectRoleScopesLookup(mock, "viewer", []string{"modules:read"})
				mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
					WithArgs("viewer").
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-viewer"))
				mock.ExpectExec("UPDATE organization_members").
					WillReturnResult(sqlmock.NewResult(0, 1))
				// The key was minted under the owner template and still asks
				// for modules:write, which viewer does not grant.
				expectOrgKeySweepScoped(mock, "user-1", "org-1", "key-idp-demoted",
					[]byte(`["modules:write"]`))

				// The login still carries "platform-team" -- it now maps to a
				// weaker role, which is the whole point: this is a reduction
				// that never touches the deprovision branch.
				if err := h.applyGroupMappings(context.Background(), "user-1", []string{"platform-team"}); err != nil {
					t.Fatalf("applyGroupMappings: %v", err)
				}
			},
		},
		{
			// Paired negative control for the row above. Deleting an API key is
			// irreversible, so sweeping on every reconciliation -- i.e. on every
			// login, for every managed org -- would destroy working credentials
			// fleet-wide.
			//
			// sqlmock cannot carry this assertion alone: an unregistered DELETE
			// returns an error, and the sweep swallows its own errors by design
			// (the authority change has already committed), so a wrongly
			// deleted key would still leave ExpectationsWereMet() green. The
			// decisive assertion is the log: the sweeper announces every key it
			// revokes and every revocation it fails, and a RETAINED key
			// produces neither line.
			site: "admin.AuthHandlers.reconcileGroupMemberships (IdP role-reassignment branch, promotion retains keys)",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				logs := captureSlogOutput(t)
				cfg := &config.Config{}
				cfg.Auth.OIDC.GroupMappings = []config.OIDCGroupMapping{
					{Group: "platform-team", Organization: "acme", Role: "publisher"},
				}
				h, err := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour),
					WithCredentialSweeper(credlifecycle.NewSweeper(
						repositories.NewUserTokenRevocationRepository(db),
						repositories.NewAPIKeyRepository(db))))
				if err != nil {
					t.Fatalf("NewAuthHandlers: %v", err)
				}

				mock.ExpectQuery("SELECT.*FROM organizations.*WHERE name").
					WithArgs("acme").
					WillReturnRows(sqlmock.NewRows(authOrgCols).
						AddRow("org-1", "acme", "Acme Corp", nil, nil, time.Now(), time.Now()))
				oldRole := "rt-viewer"
				mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE organization_id.*AND user_id").
					WillReturnRows(sqlmock.NewRows(authMemberCols).
						AddRow("org-1", "user-1", &oldRole, time.Now()))
				expectRegistryRoleFor(mock, registryRole{id: oldRole})
				expectRoleScopesLookup(mock, "publisher", []string{"modules:read", "modules:write"})
				mock.ExpectQuery("SELECT id FROM role_templates WHERE name").
					WithArgs("publisher").
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("rt-publisher"))
				mock.ExpectExec("UPDATE organization_members").
					WillReturnResult(sqlmock.NewResult(0, 1))
				// modules:read is still granted by the new template, so the key
				// asks for nothing it lost: listed, and left alone.
				expectOrgKeyList(mock, "user-1", "org-1", "key-idp-promoted", testKeyScopes)

				if err := h.applyGroupMappings(context.Background(), "user-1", []string{"platform-team"}); err != nil {
					t.Fatalf("applyGroupMappings: %v", err)
				}
				for _, forbidden := range []string{"API key revoked", "failed to revoke org-bound API key"} {
					if strings.Contains(logs.String(), forbidden) {
						t.Errorf("a promotion deleted an API key that is still within the new authority (log contains %q); logs: %s",
							forbidden, logs.String())
					}
				}
			},
		},
		{
			// #736 primary instance.
			site: "scim.Handlers.DeleteUser / DELETE /scim/v2/Users/:id",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				r := newSCIMDeprovisionRouter(db)
				mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
					WillReturnRows(scimUserRows("user-scim"))
				expectSCIMDeprovisionSweep(mock, "user-scim")

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("DELETE", "/scim/v2/Users/user-scim", nil))
				if w.Code != http.StatusNoContent {
					t.Fatalf("status = %d, want 204: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			site: "scim.Handlers.PutUser (active=false) / PUT /scim/v2/Users/:id",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				r := newSCIMDeprovisionRouter(db)
				mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
					WillReturnRows(scimUserRows("user-scim"))
				expectSCIMDeprovisionSweep(mock, "user-scim")
				mock.ExpectExec("UPDATE users").
					WillReturnResult(sqlmock.NewResult(0, 1))

				w := httptest.NewRecorder()
				req := httptest.NewRequest("PUT", "/scim/v2/Users/user-scim",
					bytes.NewBufferString(`{"userName":"jane@example.com","active":false}`))
				req.Header.Set("Content-Type", "application/json")
				r.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			site: `scim.Handlers.applyReplaceOp (path="active", false) / PATCH /scim/v2/Users/:id`,
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				r := newSCIMDeprovisionRouter(db)
				mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
					WillReturnRows(scimUserRows("user-scim"))
				expectSCIMDeprovisionSweep(mock, "user-scim")
				mock.ExpectExec("UPDATE users").
					WillReturnResult(sqlmock.NewResult(0, 1))

				w := httptest.NewRecorder()
				req := httptest.NewRequest("PATCH", "/scim/v2/Users/user-scim",
					bytes.NewBufferString(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],`+
						`"Operations":[{"op":"replace","path":"active","value":false}]}`))
				req.Header.Set("Content-Type", "application/json")
				r.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			site: `scim.Handlers.applyReplaceOp (pathless {"active":false}) / PATCH /scim/v2/Users/:id`,
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				r := newSCIMDeprovisionRouter(db)
				mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
					WillReturnRows(scimUserRows("user-scim"))
				expectSCIMDeprovisionSweep(mock, "user-scim")
				mock.ExpectExec("UPDATE users").
					WillReturnResult(sqlmock.NewResult(0, 1))

				w := httptest.NewRecorder()
				req := httptest.NewRequest("PATCH", "/scim/v2/Users/user-scim",
					bytes.NewBufferString(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],`+
						`"Operations":[{"op":"replace","value":{"active":false}}]}`))
				req.Header.Set("Content-Type", "application/json")
				r.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			// Reached through DELETE FROM organizations cascading
			// organization_members -- a reduce verb the enumeration signature's
			// vocabulary did not originally contain, which is why this site was
			// missed. The api_keys half really is handled by the FK
			// (organization_id is ON DELETE CASCADE in both schemas); the JWT
			// half is not, because a member's token carries a cross-org scope
			// union computed at login.
			site: "admin.OrganizationHandlers.DeleteOrganizationHandler / DELETE /api/v1/organizations/:id",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				h := NewOrganizationHandlers(&config.Config{}, db,
					repositories.NewNamespaceClaimRepository(db),
					repositories.NewUserTokenRevocationRepository(db))
				r := gin.New()
				r.DELETE("/organizations/:id", h.DeleteOrganizationHandler())

				mock.ExpectQuery("SELECT.*FROM organizations WHERE id").
					WillReturnRows(sqlmock.NewRows(authOrgCols).
						AddRow("org-1", "acme", "Acme Corp", nil, nil, time.Now(), time.Now()))
				mock.ExpectQuery("SELECT COUNT.*FROM namespace_claims").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
				mock.ExpectQuery("SELECT EXISTS").
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
				// Members are snapshotted BEFORE the delete: the cascade
				// removes them, so afterwards there is nobody left to sweep.
				mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
					WillReturnRows(sqlmock.NewRows(authMemberCols).
						AddRow("org-1", "user-1", nil, time.Now()))
				expectRegistryRolesForOrg(mock, registryRole{userID: "user-1"})
				mock.ExpectExec("DELETE FROM organizations").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("INSERT INTO user_token_revocations").
					WithArgs("user-1").
					WillReturnResult(sqlmock.NewResult(1, 1))
				expectOrgKeySweep(mock, "user-1", "org-1", "key-org-deleted")

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("DELETE", "/organizations/org-1", nil))
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			// Previously EXEMPTED on the false premise that
			// api_keys.user_id is ON DELETE CASCADE. It is CASCADE only in the
			// registry's legacy schema; identity.api_keys declares ON DELETE
			// SET NULL, so the delete detached the principal's keys into
			// userless org-bound rows that the namespace authorizer reads as
			// organization service credentials. The sweep runs BEFORE the
			// delete because afterwards there is no user_id left to find the
			// rows by.
			site: "admin.UserHandlers.DeleteUserHandler / DELETE /api/v1/users/:id",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				h := NewUserHandlers(&config.Config{}, db, WithUserCredentialSweeper(
					credlifecycle.NewSweeper(
						repositories.NewUserTokenRevocationRepository(db),
						repositories.NewAPIKeyRepository(db))))
				r := gin.New()
				r.DELETE("/users/:id", h.DeleteUserHandler())

				mock.ExpectQuery("SELECT.*FROM users.*WHERE id").
					WillReturnRows(scimUserRows("user-1"))
				mock.ExpectExec("INSERT INTO user_token_revocations").
					WithArgs("user-1").
					WillReturnResult(sqlmock.NewResult(1, 1))
				expectAllKeysSweep(mock, "user-1", "key-deleted-user")
				mock.ExpectExec("DELETE FROM users").
					WillReturnResult(sqlmock.NewResult(0, 1))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("DELETE", "/users/user-1", nil))
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			// EraseUser deletes api_keys inside its transaction but its JWT
			// step was an INSERT ... SELECT FROM user_sessions -- a table that
			// exists in no migration in this repository -- with its error
			// discarded. It always failed, so an "erased" user kept live
			// sessions, while the SQL text made the site LOOK swept.
			site: "services.UserService.EraseUser / POST /api/v1/admin/users/:id/erase",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				svc := services.NewUserService(db).WithCredentialSweeper(
					credlifecycle.NewSweeper(
						repositories.NewUserTokenRevocationRepository(db),
						repositories.NewAPIKeyRepository(db)))
				r := gin.New()
				r.Use(func(c *gin.Context) { c.Set("user_id", knownUserUUID) })
				r.POST("/users/:id/erase", NewGDPRHandlers(svc).EraseUserHandler())

				mock.ExpectBegin()
				mock.ExpectQuery("SELECT EXISTS").
					WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
				mock.ExpectExec("UPDATE users").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("DELETE FROM api_keys WHERE user_id").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("DELETE FROM organization_members").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
				// The real JWT mechanism: the per-user revoke-all watermark,
				// which lives on a different connection and so runs after the
				// commit.
				mock.ExpectExec("INSERT INTO user_token_revocations").
					WithArgs("user-1").
					WillReturnResult(sqlmock.NewResult(1, 1))
				// One scoped DELETE, not a list-then-revoke loop.
				mock.ExpectExec("DELETE FROM api_keys WHERE user_id").
					WithArgs("user-1").
					WillReturnResult(sqlmock.NewResult(0, 0))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("POST", "/users/user-1/erase", nil))
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: body=%s", w.Code, w.Body.String())
				}
			},
		},
		{
			// The org-bound key path is no WEAKER than the legacy unbound one:
			// a member downgraded to a read-only role template cannot publish
			// through a key issued under their old role, even though the key's
			// frozen scopes still say modules:write.
			site: "middleware.NamespaceAuthorizer.verifyKeyOwnerAuthority (org-bound API key, owner downgraded)",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				authz := middleware.NewNamespaceAuthorizer(
					repositories.NewOrganizationRepository(db),
					repositories.NewNamespaceClaimRepository(db),
					repositories.NewModuleRepository(db),
					repositories.NewProviderRepository(db))

				mock.ExpectQuery("SELECT.*FROM namespace_claims").
					WillReturnRows(sqlmock.NewRows([]string{"namespace", "organization_id", "claimed_by", "created_at"}).
						AddRow("acme", "org-1", nil, time.Now()))
				// Still a member, but the role template grants only read.
				mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
					WillReturnRows(sqlmock.NewRows(memberRoleCols).AddRow(
						"org-1", "user-1", "rt-viewer", time.Now(),
						"Alice", "alice@example.com", "viewer", "Viewer",
						[]byte(`["modules:read"]`)))
				expectRegistryRoleFor(mock, registryRole{
					id: "rt-viewer", name: "viewer", displayName: "Viewer", scopes: `["modules:read"]`,
				})

				owner := "user-1"
				r := gin.New()
				r.DELETE("/modules/:namespace/:name/:system",
					func(c *gin.Context) {
						c.Set("scopes", []string{string(auth.ScopeModulesWrite)})
						c.Set("user_id", owner)
						c.Set("api_key", &models.APIKey{
							ID:             "key-downgraded",
							UserID:         &owner,
							OrganizationID: "org-1",
							Scopes:         []string{string(auth.ScopeModulesWrite)},
						})
					},
					authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
					func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/acme/vpc/aws", nil))
				if w.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403 (downgraded owner must not publish through a stale key): body=%s",
						w.Code, w.Body.String())
				}
			},
		},
		{
			// The FIRST-CLAIM path, which previously performed no
			// authorization at all on the winning branch: resolveCallerOrg
			// returned the key's frozen organization binding as "the strongest
			// trust anchor" and authorizeOrgAccess ran only when the caller
			// LOST a concurrent claim race. A key bound to an org its owner had
			// left could claim a brand-new namespace and publish: 201, zero
			// membership queries.
			site: "middleware.NamespaceAuthorizer.resolveCallerOrg (org-bound API key, first claim, owner removed)",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				authz := middleware.NewNamespaceAuthorizer(
					repositories.NewOrganizationRepository(db),
					repositories.NewNamespaceClaimRepository(db),
					repositories.NewModuleRepository(db),
					repositories.NewProviderRepository(db))

				mock.ExpectQuery("SELECT.*FROM namespace_claims").
					WillReturnRows(sqlmock.NewRows([]string{"namespace", "organization_id", "claimed_by", "created_at"}))
				mock.ExpectQuery("SELECT DISTINCT organization_id FROM").
					WillReturnRows(sqlmock.NewRows([]string{"organization_id"}))
				// Owner is no longer a member. No INSERT INTO namespace_claims
				// is registered: a stale key must not even squat the namespace.
				mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
					WillReturnRows(sqlmock.NewRows(memberRoleCols))

				owner := "user-1"
				r := gin.New()
				r.POST("/modules",
					func(c *gin.Context) {
						c.Set("scopes", []string{string(auth.ScopeModulesWrite)})
						c.Set("user_id", owner)
						c.Set("api_key", &models.APIKey{
							ID:             "key-stale-claimer",
							UserID:         &owner,
							OrganizationID: "org-1",
							Scopes:         []string{string(auth.ScopeModulesWrite)},
						})
					},
					authz.RequirePublishAccessFromForm(auth.ScopeModulesWrite, 100<<20),
					func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"ok": true}) })

				w := httptest.NewRecorder()
				r.ServeHTTP(w, multipartPublishRequest(t, map[string]string{
					"namespace": "brand-new", "name": "vpc", "system": "aws"}))
				if w.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403 (stale key must not claim a new namespace): body=%s",
						w.Code, w.Body.String())
				}
			},
		},
		{
			// The BACKWARD population. identity.api_keys.user_id is ON DELETE
			// SET NULL, so every user deletion that happened before the sweep
			// shipped left a userless org-bound row behind -- and the authorizer
			// read exactly those rows as "organization service credentials",
			// exempt from the membership check. They are not: the registry mints
			// keys only through CreateAPIKeyHandler (UserID from the
			// authenticated caller) and RotateAPIKeyHandler (copies it), so no
			// supported path produces one. The branch fails closed, which covers
			// the population without depending on migration 000050 having run.
			//
			// No membership query is registered: there is no owner to look up,
			// and the refusal must not depend on one.
			site: "middleware.NamespaceAuthorizer.verifyKeyOwnerAuthority (userless org-bound key orphaned by a user deletion)",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				authz := middleware.NewNamespaceAuthorizer(
					repositories.NewOrganizationRepository(db),
					repositories.NewNamespaceClaimRepository(db),
					repositories.NewModuleRepository(db),
					repositories.NewProviderRepository(db))

				mock.ExpectQuery("SELECT.*FROM namespace_claims").
					WillReturnRows(sqlmock.NewRows([]string{"namespace", "organization_id", "claimed_by", "created_at"}).
						AddRow("acme", "org-1", nil, time.Now()))

				r := gin.New()
				r.DELETE("/modules/:namespace/:name/:system",
					func(c *gin.Context) {
						c.Set("scopes", []string{string(auth.ScopeModulesWrite)})
						c.Set("api_key", &models.APIKey{
							ID:             "key-orphaned",
							UserID:         nil,
							OrganizationID: "org-1",
							Scopes:         []string{string(auth.ScopeModulesWrite)},
						})
					},
					authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
					func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/acme/vpc/aws", nil))
				if w.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403 (a key detached by a user deletion must not authorize): body=%s",
						w.Code, w.Body.String())
				}
			},
		},
		{
			// Complementary use-time control: an API key whose org binding is
			// stale (owner no longer a member) must not authorize the namespace,
			// even though nothing swept the key. This is what makes the class
			// non-exploitable for any lifecycle site the sweep might miss.
			site: "middleware.NamespaceAuthorizer.authorizeOrgAccess (org-bound API key, owner no longer a member)",
			run: func(t *testing.T, db *sql.DB, mock sqlmock.Sqlmock) {
				authz := middleware.NewNamespaceAuthorizer(
					repositories.NewOrganizationRepository(db),
					repositories.NewNamespaceClaimRepository(db),
					repositories.NewModuleRepository(db),
					repositories.NewProviderRepository(db))

				// Namespace "acme" is claimed by the very org the key is bound to.
				mock.ExpectQuery("SELECT.*FROM namespace_claims").
					WillReturnRows(sqlmock.NewRows([]string{"namespace", "organization_id", "claimed_by", "created_at"}).
						AddRow("acme", "org-1", nil, time.Now()))
				// The key's owner is no longer a member of org-1.
				mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
					WillReturnRows(sqlmock.NewRows(memberRoleCols))

				owner := "user-1"
				r := gin.New()
				r.DELETE("/modules/:namespace/:name/:system",
					func(c *gin.Context) {
						c.Set("scopes", []string{string(auth.ScopeModulesWrite)})
						c.Set("user_id", owner)
						c.Set("api_key", &models.APIKey{
							ID:             "key-stale",
							UserID:         &owner,
							OrganizationID: "org-1",
							Scopes:         []string{string(auth.ScopeModulesWrite)},
						})
					},
					authz.RequireNamespaceAccessFromPath(auth.ScopeModulesWrite),
					func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest("DELETE", "/modules/acme/vpc/aws", nil))
				if w.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403 (stale org-bound API key must fail closed): body=%s",
						w.Code, w.Body.String())
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.site, func(t *testing.T) {
			db, mock, err := newSQLMock()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			tc.run(t, db, mock)

			// Every registered statement must have been issued. For the sweep
			// rows this is the assertion that the API-key revocation actually
			// happened; sqlmock reports an unfulfilled expectation when it did
			// not.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("credential sweep incomplete for %s: %v", tc.site, err)
			}
		})
	}
}
