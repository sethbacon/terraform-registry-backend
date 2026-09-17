package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// ---------------------------------------------------------------------------
// The `admin` scope may never be written to an API key (issue #766,
// migration 000054)
// ---------------------------------------------------------------------------
//
// Platform-admin authority now derives only from the platform_admins carrier,
// and middleware runs platformadmin.KeyScopes over every key on every request.
// An admin-bearing key would therefore be INERT rather than powerful, so the
// three write surfaces refuse it outright instead of minting a credential that
// reports an authority it will never exercise.
//
// These assert the REFUSAL CODE as well as the fact of refusal: create and
// update answer 400 because no role the caller could hold would make the body
// acceptable, while rotate answers 403 because the offending scopes are
// existing state rather than something the caller submitted.

func TestCreateAPIKey_AdminScopeRefused(t *testing.T) {
	// No DB expectations: the guard runs before the organization is resolved,
	// so a query here would mean the refusal happened too late.
	_, r := newAPIKeyRouter(t, "user-1", []string{"admin"})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys",
		jsonBody(map[string]interface{}{
			"name":            "My Key",
			"organization_id": "org-1",
			"scopes":          []string{"admin"},
		})))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
	assertNamesPlatformAdminRoute(t, w.Body.String())
}

func TestUpdateAPIKey_AdminScopeRefused(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", []string{"admin"})
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").WillReturnRows(sampleAKRow())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", "/apikeys/key-1",
		jsonBody(map[string]interface{}{"scopes": []string{"modules:read", "admin"}})))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
	assertNamesPlatformAdminRoute(t, w.Body.String())
}

// A key minted before migration 000054 can still carry `admin` in its stored
// scopes; rotation must not copy it onto the new row. The ceiling below would
// also refuse, so the assertion is on the message: only the guard names the
// remedy, which is what tells an operator the key itself is the problem.
func TestRotateAPIKey_AdminScopeRefused(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", []string{"admin"})
	mock.ExpectQuery("SELECT.*FROM api_keys WHERE id").
		WillReturnRows(sqlmock.NewRows(akCols).AddRow(
			"key-1", "user-1", "org-1", "Legacy Key", nil, "hashedkey", "tfr_abc123",
			[]byte(`["admin"]`), nil, nil, nil, time.Now(),
		))

	roleTemplateID := "role-owner"
	roleName := "org_owner"
	roleDisplay := "Organization Owner"
	ownerScopes := []byte(`["organizations:write","modules:read","modules:write"]`)
	mock.ExpectQuery("SELECT.*FROM organization_members.*LEFT JOIN").
		WillReturnRows(sqlmock.NewRows(memberRoleCols).AddRow(
			"org-1", "user-1", &roleTemplateID, time.Now(),
			"Alice", "alice@example.com",
			&roleName, &roleDisplay, ownerScopes,
		))
	expectRegistryRoleFor(mock, registryRole{
		id: roleTemplateID, name: roleName, displayName: roleDisplay, scopes: string(ownerScopes),
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys/key-1/rotate",
		jsonBody(map[string]interface{}{"grace_period_hours": 0})))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "before rotating it") {
		t.Errorf("refusal does not tell the operator to strip the scope from the key: %s", w.Body.String())
	}
}

func assertNamesPlatformAdminRoute(t *testing.T, body string) {
	t.Helper()
	if !strings.Contains(body, "platform-admins") {
		t.Errorf("refusal does not name the route that does grant platform administration: %s", body)
	}
}

// ---------------------------------------------------------------------------
// The mint ceiling must admit exactly what authentication admits
// ---------------------------------------------------------------------------
//
// currentKeyScopes resolves the caller's stored scopes against the owner's role
// template with auth.HasScope, which honours readWritePairs. A ceiling that
// tested set membership instead was STRICTER than authentication: an org owner
// holding organizations:write was refused organizations:read, a scope the
// minted key would then have carried perfectly well.
//
// Confirmed in production before the fix (registry.brunswick.com, 2026-09-17):
// POST /api/v1/apikeys {"scopes":["organizations:read"]} answered 403 with
// allowed_scopes listing organizations:write.
func TestCreateAPIKey_ImpliedReadScopeAccepted(t *testing.T) {
	mock, r := newAPIKeyRouter(t, "user-1", nil)

	roleTemplateID := "role-owner"
	roleName := "org_owner"
	roleDisplay := "Organization Owner"
	writeOnly := []byte(`["organizations:write"]`)
	mock.ExpectQuery("SELECT.*FROM organization_members.*WHERE").
		WillReturnRows(sqlmock.NewRows(memberRoleCols).AddRow(
			"org-1", "user-1", &roleTemplateID, time.Now(),
			"Alice", "alice@example.com",
			&roleName, &roleDisplay, writeOnly,
		))
	expectRegistryRoleFor(mock, registryRole{
		id: roleTemplateID, name: roleName, displayName: roleDisplay, scopes: string(writeOnly),
	})
	mock.ExpectExec("INSERT INTO api_keys").WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/apikeys",
		jsonBody(map[string]interface{}{
			"name":            "My Key",
			"organization_id": "org-1",
			"scopes":          []string{"organizations:read"},
		})))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (write implies read, so the key may carry it): body=%s",
			w.Code, w.Body.String())
	}
}
