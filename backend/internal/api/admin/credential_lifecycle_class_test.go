package admin

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
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
)

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

// expectOrgKeySweep registers the two statements that revoke every API key
// userID holds in orgID: the org-scoped list, then the delete of the one key
// it returns.
func expectOrgKeySweep(mock sqlmock.Sqlmock, userID, orgID, keyID string) {
	mock.ExpectQuery("(?s)FROM api_keys ak.*ak.organization_id").
		WithArgs(userID, orgID).
		WillReturnRows(sqlmock.NewRows(akListCols).
			AddRow(keyID, userID, orgID, "CI Key", nil, "hashedkey", "tfr_abc123",
				testKeyScopes, nil, nil, nil, time.Now(), nil))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs(keyID).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// expectAllKeysSweep registers the statements that revoke every API key userID
// holds anywhere -- the whole-principal offboarding sweep.
func expectAllKeysSweep(mock sqlmock.Sqlmock, userID, keyID string) {
	mock.ExpectQuery("(?s)FROM api_keys ak.*WHERE ak.user_id").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows(akListCols).
			AddRow(keyID, userID, "org-1", "CI Key", nil, "hashedkey", "tfr_abc123",
				testKeyScopes, nil, nil, nil, time.Now(), nil))
	mock.ExpectExec("DELETE FROM api_keys WHERE id").
		WithArgs(keyID).
		WillReturnResult(sqlmock.NewResult(1, 1))
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
	r.PUT("/scim/v2/Users/:id", h.PutUser())
	r.PATCH("/scim/v2/Users/:id", h.PatchUser())
	r.DELETE("/scim/v2/Users/:id", h.DeleteUser())
	return r
}

// expectSCIMDeprovisionSweep registers the shared tail of every SCIM
// deprovisioning path: strip memberships, move the JWT watermark, revoke all
// API keys.
func expectSCIMDeprovisionSweep(mock sqlmock.Sqlmock, userID string) {
	mock.ExpectExec("DELETE FROM organization_members").
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO user_token_revocations").
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	expectAllKeysSweep(mock, userID, "key-scim")
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

				mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
					WillReturnRows(sqlmock.NewRows([]string{"scopes"}).AddRow([]byte(`[]`)))
				mock.ExpectQuery("SELECT.*FROM organization_members WHERE organization_id").
					WillReturnRows(sampleOrgMemberRowWithRole(oldRoleTemplateUUID))
				mock.ExpectExec("UPDATE organization_members").
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectExec("INSERT INTO user_token_revocations").
					WithArgs("user-1").
					WillReturnResult(sqlmock.NewResult(1, 1))
				expectOrgKeySweep(mock, "user-1", "org-1", "key-rerole")
				mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
					WillReturnRows(sampleMemberWithRoleRow())

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

				mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
					WillReturnRows(sampleRTRow())
				mock.ExpectExec("UPDATE role_templates.*SET display_name").
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_members").
					WillReturnRows(sqlmock.NewRows([]string{"user_id", "organization_id"}).
						AddRow("member-1", "org-1"))
				mock.ExpectExec("INSERT INTO user_token_revocations").
					WithArgs("member-1").
					WillReturnResult(sqlmock.NewResult(1, 1))
				expectOrgKeySweep(mock, "member-1", "org-1", "key-rt-edit")

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

				mock.ExpectQuery("SELECT.*FROM role_templates WHERE id").
					WillReturnRows(sampleRTRow())
				mock.ExpectQuery("SELECT DISTINCT user_id, organization_id FROM organization_members").
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
			db, mock, err := sqlmock.New()
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
