package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// boolPtr returns a pointer to b for building optional claim values.
func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// enforceEmailVerified
// ---------------------------------------------------------------------------

func TestEnforceEmailVerified(t *testing.T) {
	cases := []struct {
		name     string
		verified *bool
		require  bool
		wantErr  error
	}{
		{"verified true, not required", boolPtr(true), false, nil},
		{"verified true, required", boolPtr(true), true, nil},
		{"explicit false, not required", boolPtr(false), false, errEmailNotVerified},
		{"explicit false, required", boolPtr(false), true, errEmailNotVerified},
		{"absent, not required", nil, false, nil},
		{"absent, required", nil, true, errEmailVerifiedMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enforceEmailVerified(tc.verified, tc.require)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("enforceEmailVerified(%v, %v) = %v, want %v", tc.verified, tc.require, err, tc.wantErr)
			}
		})
	}
}

// fakeClaimReader satisfies claimReader by unmarshaling a fixed claim set.
type fakeClaimReader struct {
	emailVerified interface{} // nil = claim absent; otherwise bool
	err           error
}

func (f fakeClaimReader) Claims(v interface{}) error {
	if f.err != nil {
		return f.err
	}
	// Mimic json unmarshal into the {EmailVerified *bool} target.
	target, ok := v.(*struct {
		EmailVerified *bool `json:"email_verified"`
	})
	if !ok {
		return nil
	}
	if f.emailVerified != nil {
		b := f.emailVerified.(bool)
		target.EmailVerified = &b
	}
	return nil
}

func TestEmailVerifiedClaim(t *testing.T) {
	if got := emailVerifiedClaim(fakeClaimReader{emailVerified: true}); got == nil || !*got {
		t.Errorf("expected true, got %v", got)
	}
	if got := emailVerifiedClaim(fakeClaimReader{emailVerified: false}); got == nil || *got {
		t.Errorf("expected false, got %v", got)
	}
	if got := emailVerifiedClaim(fakeClaimReader{emailVerified: nil}); got != nil {
		t.Errorf("expected nil (absent), got %v", *got)
	}
	if got := emailVerifiedClaim(fakeClaimReader{err: errors.New("boom")}); got != nil {
		t.Errorf("expected nil on claims error, got %v", *got)
	}
}

// ---------------------------------------------------------------------------
// guardEmailRebind — cross-provider account takeover guard
// ---------------------------------------------------------------------------

// newAuthHandlersWithMock builds an AuthHandlers backed by a sqlmock DB.
func newAuthHandlersWithMock(t *testing.T) (*AuthHandlers, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{}
	h, err := NewAuthHandlers(cfg, db, nil, nil, auth.NewMemoryStateStore(time.Hour))
	if err != nil {
		t.Fatalf("NewAuthHandlers: %v", err)
	}
	return h, mock
}

func TestGuardEmailRebind_BlankEmailSkips(t *testing.T) {
	h, _ := newAuthHandlersWithMock(t)
	// No query expected when email is blank.
	if err := h.guardEmailRebind(t.Context(), "oidc-sub", ""); err != nil {
		t.Fatalf("expected nil for blank email, got %v", err)
	}
}

func TestGuardEmailRebind_NoExistingUser(t *testing.T) {
	h, mock := newAuthHandlersWithMock(t)
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("new@example.com").
		WillReturnRows(sqlmock.NewRows(authUserCols)) // no rows
	if err := h.guardEmailRebind(t.Context(), "sub-1", "new@example.com"); err != nil {
		t.Fatalf("expected nil (free to create), got %v", err)
	}
}

func TestGuardEmailRebind_PreProvisionedNullSub(t *testing.T) {
	h, mock := newAuthHandlersWithMock(t)
	// Existing user with NULL oidc_sub (pre-provisioned) — linking allowed.
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("invited@example.com").
		WillReturnRows(sqlmock.NewRows(authUserCols).
			AddRow("u1", "invited@example.com", "Invited", nil, time.Now(), time.Now()))
	if err := h.guardEmailRebind(t.Context(), "sub-new", "invited@example.com"); err != nil {
		t.Fatalf("expected nil for pre-provisioned link, got %v", err)
	}
}

func TestGuardEmailRebind_SameSubAllowed(t *testing.T) {
	h, mock := newAuthHandlersWithMock(t)
	existingSub := "sub-same"
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("alice@example.com").
		WillReturnRows(sqlmock.NewRows(authUserCols).
			AddRow("u1", "alice@example.com", "Alice", &existingSub, time.Now(), time.Now()))
	if err := h.guardEmailRebind(t.Context(), "sub-same", "alice@example.com"); err != nil {
		t.Fatalf("expected nil for same-sub re-login, got %v", err)
	}
}

func TestGuardEmailRebind_DifferentSubRejected(t *testing.T) {
	h, mock := newAuthHandlersWithMock(t)
	existingSub := "oidc-sub-victim"
	mock.ExpectQuery("SELECT.*FROM users.*WHERE email").
		WithArgs("victim@example.com").
		WillReturnRows(sqlmock.NewRows(authUserCols).
			AddRow("u1", "victim@example.com", "Victim", &existingSub, time.Now(), time.Now()))
	// Attacker logs in via a different provider asserting the victim's email.
	err := h.guardEmailRebind(t.Context(), "ldap:cn=attacker", "victim@example.com")
	if !errors.Is(err, errEmailBoundToAnotherIdentity) {
		t.Fatalf("expected errEmailBoundToAnotherIdentity, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// roleScopesPermittedBy — privilege ceiling for role assignment (#2)
// ---------------------------------------------------------------------------

func TestRoleScopesPermittedBy(t *testing.T) {
	cases := []struct {
		name         string
		callerScopes []string
		roleScopes   []string
		want         bool
	}{
		{"empty role always ok", []string{"modules:read"}, nil, true},
		{"subset permitted", []string{"modules:read", "modules:write"}, []string{"modules:read"}, true},
		{"write implies read", []string{"modules:write"}, []string{"modules:read"}, true},
		{"exceeds caller denied", []string{"modules:read"}, []string{"modules:write"}, false},
		{"admin role needs admin caller", []string{"organizations:write"}, []string{"admin"}, false},
		{"admin caller can grant admin", []string{"admin"}, []string{"admin"}, true},
		{"admin caller can grant anything", []string{"admin"}, []string{"modules:write", "users:write"}, true},
		{"partial overlap denied", []string{"modules:read", "providers:read"}, []string{"modules:read", "users:write"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := auth.RoleScopesPermittedBy(tc.callerScopes, tc.roleScopes); got != tc.want {
				t.Errorf("auth.RoleScopesPermittedBy(%v, %v) = %v, want %v", tc.callerScopes, tc.roleScopes, got, tc.want)
			}
		})
	}
}

// checkRoleAssignment short-circuits on a nil template without touching the DB.
func TestCheckRoleAssignment_NilTemplateAllowed(t *testing.T) {
	h := &OrganizationHandlers{}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if chk := h.checkRoleAssignment(c, nil); !chk.allowed {
		t.Fatalf("nil role template should be allowed, got %+v", chk)
	}
	blank := ""
	if chk := h.checkRoleAssignment(c, &blank); !chk.allowed {
		t.Fatalf("blank role template should be allowed, got %+v", chk)
	}
}

func TestCheckRoleAssignment_InvalidUUID(t *testing.T) {
	h := &OrganizationHandlers{}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	bad := "not-a-uuid"
	chk := h.checkRoleAssignment(c, &bad)
	if chk.allowed || chk.status != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid uuid, got %+v", chk)
	}
}

// Ensure auth scope constants resolve (guards against scope-string drift).
func TestRoleScopeCeiling_UsesAdminWildcard(t *testing.T) {
	if !auth.HasScope([]string{string(auth.ScopeAdmin)}, auth.ScopeModulesWrite) {
		t.Fatal("admin wildcard should satisfy any scope")
	}
}
