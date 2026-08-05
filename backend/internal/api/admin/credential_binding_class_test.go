package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// ---------------------------------------------------------------------------
// Class test: an authority ceiling must be bound to the PRESENTING credential,
// not to the credential owner's user record (issue #733)
// ---------------------------------------------------------------------------
//
// DEFECT CLASS
//
//	A handler decides how much authority a request may exercise -- or GRANT --
//	by reading the caller's USER record (organization membership + role
//	template) and never asking what the credential in front of it actually
//	carries. Where the two differ, the narrower one is the credential, and
//	ignoring it makes scoping a machine credential decorative: a key issued
//	with modules:read could mint, widen or rotate its way up to everything its
//	owner holds, including the platform-wide admin wildcard. No interactive
//	session is needed and CSRFMiddleware exempts API-key callers, so possession
//	of one leaked narrow key was possession of its owner's maximum authority.
//
// The table below is the class on the minting axis: three operations that write
// a scope set (create, update, rotate) x three principals (an interactive JWT
// session, an API key strictly narrower than its owner, an API key equal to its
// owner) x both directions of the decision.
//
// BOTH DIRECTIONS ARE ASSERTED ON PURPOSE. A table that only proves denials
// passes just as happily when the ceiling resolver returns the empty set and
// refuses everyone -- which is itself a defect, and one that a
// deny-everything "fix" would hide. Every principal therefore has a row it
// must still be ALLOWED, and the narrow key is allowed precisely the scope it
// itself holds.
//
// Siblings of the class that do not write an API key scope set are covered
// underneath the table: role assignment (role_ceiling.go) and token refresh
// (auth.go), which was the same root cause with the credential families
// swapped -- a machine credential exchanged for a session token carrying its
// owner's whole cross-organization scope union.

// ownerRoleScopes is what the key owner's role template grants in org-1: the
// admin wildcard, i.e. the maximum authority a narrowed key must not reach.
var ownerRoleScopes = []byte(`["admin"]`)

// credBindingPrincipal is one authenticated caller shape.
type credBindingPrincipal struct {
	name string
	// keyScopes is nil for an interactive JWT session and the presenting API
	// key's own scopes otherwise.
	keyScopes []string
	// sessionScopes is what AuthMiddleware puts in c.Get("scopes") -- the JWT's
	// embedded union for a session, the key's derived scopes for a key.
	sessionScopes []string
}

var credBindingPrincipals = []credBindingPrincipal{
	{
		// The interactive path keeps today's user-derived ceiling: a browser
		// session IS the user's full authority, so nothing narrows it.
		name:          "jwt session",
		sessionScopes: []string{"admin"},
	},
	{
		// The escalation vector: a key deliberately scoped down, owned by a
		// principal holding the admin role template in the same organization.
		name:          "api key narrower than owner",
		keyScopes:     []string{"modules:read"},
		sessionScopes: []string{"modules:read"},
	},
	{
		// The control: a key that carries everything its owner does must not
		// lose anything to the new ceiling.
		name:          "api key equal to owner",
		keyScopes:     []string{"admin"},
		sessionScopes: []string{"admin"},
	},
}

// newCredBindingRouter mounts the API key handlers with the context
// AuthMiddleware would have produced for p.
func newCredBindingRouter(t *testing.T, p credBindingPrincipal) (sqlmock.Sqlmock, *gin.Engine) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewAPIKeyHandlers(&config.Config{}, db)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		c.Set("scopes", p.sessionScopes)
		if p.keyScopes == nil {
			c.Set("auth_method", "jwt")
		} else {
			owner := "user-1"
			c.Set("auth_method", "api_key")
			c.Set("organization_id", "org-1")
			c.Set("api_key", &models.APIKey{
				ID:             "presenting-key",
				UserID:         &owner,
				OrganizationID: "org-1",
				Scopes:         p.keyScopes,
			})
		}
		c.Next()
	})
	r.POST("/apikeys", h.CreateAPIKeyHandler())
	r.PUT("/apikeys/:id", h.UpdateAPIKeyHandler())
	r.POST("/apikeys/:id/rotate", h.RotateAPIKeyHandler())
	return mock, r
}

// ownerMemberRow is the org-1 membership of user-1 under the admin role
// template -- the user-derived half of every ceiling in this file.
func ownerMemberRow() *sqlmock.Rows {
	roleTemplateID := "role-owner"
	roleName := "owner"
	roleDisplay := "Owner"
	return sqlmock.NewRows(memberRoleCols).AddRow(
		"org-1", "user-1", &roleTemplateID, time.Now(),
		"Alice", "alice@example.com",
		&roleName, &roleDisplay,
		ownerRoleScopes,
	)
}

// storedKeyRow is an existing api_keys row owned by user-1 in org-1 carrying
// scopes -- the subject of update and rotate.
func storedKeyRow(scopes string) *sqlmock.Rows {
	return sqlmock.NewRows(akCols).AddRow(
		"key-1", "user-1", "org-1", "CI Key", nil, "hashedkey", "tfr_abc123",
		[]byte(scopes), nil, nil, nil, time.Now(),
	)
}

func TestCredentialBindingClass_KeyMinting(t *testing.T) {
	// requested is the scope set the operation would write. "admin" is the
	// escalation; "modules:read" is the scope the narrow key legitimately
	// holds, and is what proves the ceiling has not collapsed to empty.
	cases := []struct {
		op        string
		requested string
	}{
		{"create", "admin"},
		{"create", "modules:read"},
		{"update", "admin"},
		{"update", "modules:read"},
		{"rotate", "admin"},
		{"rotate", "modules:read"},
	}

	for _, p := range credBindingPrincipals {
		for _, tc := range cases {
			// A key may write a scope set only if it holds those scopes
			// itself; a session is bounded solely by the owner's role
			// template, which here is the admin wildcard.
			allowed := p.keyScopes == nil || auth.HasScope(p.keyScopes, auth.Scope(tc.requested))

			t.Run(tc.op+"/"+p.name+"/"+tc.requested, func(t *testing.T) {
				mock, r := newCredBindingRouter(t, p)
				w := httptest.NewRecorder()

				switch tc.op {
				case "create":
					mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
						WillReturnRows(ownerMemberRow())
					if allowed {
						mock.ExpectExec("INSERT INTO api_keys").
							WillReturnResult(sqlmock.NewResult(1, 1))
					}
					r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/apikeys",
						jsonBody(map[string]interface{}{
							"name":            "minted",
							"organization_id": "org-1",
							"scopes":          []string{tc.requested},
						})))

				case "update":
					mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").
						WillReturnRows(storedKeyRow(`["modules:read"]`))
					mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
						WillReturnRows(ownerMemberRow())
					if allowed {
						mock.ExpectExec("UPDATE api_keys.*SET name").
							WillReturnResult(sqlmock.NewResult(1, 1))
					}
					r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/apikeys/key-1",
						jsonBody(map[string]interface{}{
							"scopes": []string{tc.requested},
						})))

				case "rotate":
					// Rotation writes the OLD key's scopes into a new row, so
					// the old row's stored scopes are the set under test.
					mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").
						WillReturnRows(storedKeyRow(`["` + tc.requested + `"]`))
					mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
						WillReturnRows(ownerMemberRow())
					if allowed {
						mock.ExpectExec("INSERT INTO api_keys").
							WillReturnResult(sqlmock.NewResult(1, 1))
						mock.ExpectExec("DELETE FROM api_keys").
							WillReturnResult(sqlmock.NewResult(1, 1))
					}
					r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/apikeys/key-1/rotate",
						jsonBody(map[string]interface{}{"grace_period_hours": 0})))
				}

				if allowed {
					if w.Code != http.StatusOK && w.Code != http.StatusCreated {
						t.Fatalf("%s with %q by %s: status = %d, want 2xx (a legitimate request must still succeed): body=%s",
							tc.op, tc.requested, p.name, w.Code, w.Body.String())
					}
					// The minted scope set must be exactly what was asked for:
					// a ceiling that silently narrows is as wrong as one that
					// silently widens.
					if got := mintedScopes(t, w); got != "" && got != tc.requested {
						t.Fatalf("%s by %s minted scopes %q, want %q", tc.op, p.name, got, tc.requested)
					}
					return
				}
				if w.Code != http.StatusForbidden {
					t.Fatalf("%s with %q by %s: status = %d, want 403 (a credential may not write a scope it does not hold): body=%s",
						tc.op, tc.requested, p.name, w.Code, w.Body.String())
				}
			})
		}
	}
}

// mintedScopes reads the scope set a successful create/rotate wrote back, or
// "" when the response carries none (update returns the whole key object).
func mintedScopes(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Scopes []string `json:"scopes"`
		NewKey struct {
			Scopes []string `json:"scopes"`
		} `json:"new_key"`
		Key struct {
			Scopes []string `json:"scopes"`
		} `json:"key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		return ""
	}
	for _, s := range [][]string{body.Scopes, body.NewKey.Scopes, body.Key.Scopes} {
		if len(s) == 1 {
			return s[0]
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Sibling: role assignment (role_ceiling.go)
// ---------------------------------------------------------------------------

// TestCredentialBindingClass_RoleAssignment covers the same root cause on a
// different minting surface. checkRoleAssignment derives the caller's
// assignment ceiling from their scopes in the target organization -- a USER
// record -- so a key scoped to organizations:write, owned by an org owner,
// could assign that owner's admin role template to any member. Assigning a
// role is minting authority by another name.
func TestCredentialBindingClass_RoleAssignment(t *testing.T) {
	adminRoleID := "33333333-3333-3333-3333-333333333333"

	tests := []struct {
		name      string
		keyScopes []string
		roleScope string
		want      bool
	}{
		{"jwt session may assign the org owner role", nil, "organizations:write", true},
		{"narrow key may not assign a role beyond its own scopes", []string{"modules:read"}, "organizations:write", false},
		{"narrow key may still assign a role within its own scopes", []string{"modules:read"}, "modules:read", true},
		{"key equal to owner may assign the org owner role", []string{"organizations:write"}, "organizations:write", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()
			h := &OrganizationHandlers{db: db, orgRepo: repositories.NewOrganizationRepository(db)}

			mock.ExpectQuery("SELECT scopes FROM role_templates WHERE id").
				WillReturnRows(sqlmock.NewRows([]string{"scopes"}).
					AddRow([]byte(`["` + tt.roleScope + `"]`)))
			// The caller's role in the target org grants both scopes, so the
			// user-derived ceiling alone permits every row here; only the
			// credential half can deny one.
			mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
				WillReturnRows(sqlmock.NewRows(orgMembersWithUserCols).AddRow(
					"org-1", "caller-1", "role-owner", time.Now(),
					"Alice", "alice@example.com", "owner", "Owner",
					[]byte(`["organizations:write","modules:read"]`),
				))

			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPut, "/organizations/org-1/members/u", nil)
			c.Params = gin.Params{{Key: "id", Value: "org-1"}}
			c.Set("user_id", "caller-1")
			if tt.keyScopes == nil {
				c.Set("auth_method", "jwt")
				c.Set("scopes", []string{"organizations:write", "modules:read"})
			} else {
				owner := "caller-1"
				c.Set("auth_method", "api_key")
				c.Set("scopes", tt.keyScopes)
				c.Set("api_key", &models.APIKey{
					UserID: &owner, OrganizationID: "org-1", Scopes: tt.keyScopes,
				})
			}

			chk := h.checkRoleAssignment(c, &adminRoleID)
			if chk.allowed != tt.want {
				t.Fatalf("allowed = %v, want %v (status %d)", chk.allowed, tt.want, chk.status)
			}
			if !tt.want && chk.status != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", chk.status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Sibling: session-token refresh (auth.go)
// ---------------------------------------------------------------------------

// TestCredentialBindingClass_RefreshRejectsMachineCredential covers the same
// root cause across credential FAMILIES. RefreshHandler mints a session token
// from GetUserCombinedScopes -- the owner's union across every organization --
// so honouring it for an API key exchanged a narrowed, organization-bound
// machine credential for an unbounded session carrying the owner's whole
// authority. There is no ceiling to intersect on a session token, so the
// families are simply not interchangeable.
func TestCredentialBindingClass_RefreshRejectsMachineCredential(t *testing.T) {
	tests := []struct {
		name       string
		authMethod string
		apiKey     *models.APIKey
		wantStatus int
	}{
		{"interactive header session refreshes", "jwt", nil, http.StatusOK},
		{"interactive cookie session refreshes", "jwt_cookie", nil, http.StatusOK},
		{"api key is refused", "api_key", &models.APIKey{Scopes: []string{"modules:read"}}, http.StatusForbidden},
		{"unrecorded auth method is refused", "", nil, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			h, err := NewAuthHandlers(&config.Config{}, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
			if err != nil {
				t.Fatalf("NewAuthHandlers: %v", err)
			}
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("user_id", "user-1")
				if tt.authMethod != "" {
					c.Set("auth_method", tt.authMethod)
				}
				if tt.apiKey != nil {
					c.Set("api_key", tt.apiKey)
				}
				c.Next()
			})
			r.POST("/auth/refresh", h.RefreshHandler())

			if tt.wantStatus == http.StatusOK {
				mock.ExpectQuery("SELECT.*FROM users WHERE id").
					WillReturnRows(sqlmock.NewRows(authUserCols).
						AddRow("user-1", "refresh@example.com", "Refresh User", nil, time.Now(), time.Now()))
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/refresh", nil))

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: body=%s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}
