package models

import (
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// UserWithOrgRoles.GetAllowedScopes
// ---------------------------------------------------------------------------

func TestGetAllowedScopes(t *testing.T) {
	t.Run("empty memberships returns empty slice", func(t *testing.T) {
		u := &UserWithOrgRoles{}
		scopes := u.GetAllowedScopes()
		if len(scopes) != 0 {
			t.Errorf("GetAllowedScopes() len = %d, want 0", len(scopes))
		}
	})

	t.Run("single membership with scopes", func(t *testing.T) {
		u := &UserWithOrgRoles{
			Memberships: []UserMembership{
				{OrganizationID: "org1", RoleTemplateScopes: []string{"providers:read", "modules:write"}},
			},
		}
		scopes := u.GetAllowedScopes()
		if len(scopes) != 2 {
			t.Errorf("GetAllowedScopes() len = %d, want 2", len(scopes))
		}
		sort.Strings(scopes)
		if scopes[0] != "modules:write" || scopes[1] != "providers:read" {
			t.Errorf("GetAllowedScopes() = %v, want [modules:write providers:read]", scopes)
		}
	})

	t.Run("overlapping scopes across memberships are deduplicated", func(t *testing.T) {
		u := &UserWithOrgRoles{
			Memberships: []UserMembership{
				{OrganizationID: "org1", RoleTemplateScopes: []string{"admin", "providers:read"}},
				{OrganizationID: "org2", RoleTemplateScopes: []string{"providers:read", "modules:write"}},
			},
		}
		scopes := u.GetAllowedScopes()
		// 3 unique scopes: admin, providers:read, modules:write
		if len(scopes) != 3 {
			t.Errorf("GetAllowedScopes() len = %d, want 3 (deduplicated)", len(scopes))
		}
		scopeSet := make(map[string]bool)
		for _, s := range scopes {
			scopeSet[s] = true
		}
		for _, want := range []string{"admin", "providers:read", "modules:write"} {
			if !scopeSet[want] {
				t.Errorf("GetAllowedScopes() missing expected scope %q", want)
			}
		}
	})

	t.Run("membership with empty scope list", func(t *testing.T) {
		u := &UserWithOrgRoles{
			Memberships: []UserMembership{
				{OrganizationID: "org1", RoleTemplateScopes: []string{}},
			},
		}
		scopes := u.GetAllowedScopes()
		if len(scopes) != 0 {
			t.Errorf("GetAllowedScopes() len = %d, want 0", len(scopes))
		}
	})

	t.Run("nil membership scopes treated as empty", func(t *testing.T) {
		u := &UserWithOrgRoles{
			Memberships: []UserMembership{
				{OrganizationID: "org1", RoleTemplateScopes: nil},
			},
		}
		scopes := u.GetAllowedScopes()
		if len(scopes) != 0 {
			t.Errorf("GetAllowedScopes() len = %d, want 0", len(scopes))
		}
	})
}

// ---------------------------------------------------------------------------
// UserWithOrgRoles.HasAdminScope
// ---------------------------------------------------------------------------

func TestHasAdminScope(t *testing.T) {
	t.Run("empty memberships returns false", func(t *testing.T) {
		u := &UserWithOrgRoles{}
		if u.HasAdminScope() {
			t.Error("HasAdminScope() = true for empty memberships, want false")
		}
	})

	t.Run("no admin scope returns false", func(t *testing.T) {
		u := &UserWithOrgRoles{
			Memberships: []UserMembership{
				{RoleTemplateScopes: []string{"providers:read", "modules:write"}},
			},
		}
		if u.HasAdminScope() {
			t.Error("HasAdminScope() = true when no admin scope present, want false")
		}
	})

	t.Run("admin scope present returns true", func(t *testing.T) {
		u := &UserWithOrgRoles{
			Memberships: []UserMembership{
				{RoleTemplateScopes: []string{"providers:read", "admin", "modules:write"}},
			},
		}
		if !u.HasAdminScope() {
			t.Error("HasAdminScope() = false when admin scope present, want true")
		}
	})

	t.Run("admin scope in second membership returns true", func(t *testing.T) {
		u := &UserWithOrgRoles{
			Memberships: []UserMembership{
				{RoleTemplateScopes: []string{"providers:read"}},
				{RoleTemplateScopes: []string{"admin"}},
			},
		}
		if !u.HasAdminScope() {
			t.Error("HasAdminScope() = false when admin scope in second membership, want true")
		}
	})

	t.Run("partial match does not count (admin:read is not admin)", func(t *testing.T) {
		u := &UserWithOrgRoles{
			Memberships: []UserMembership{
				{RoleTemplateScopes: []string{"admin:read", "admin:write"}},
			},
		}
		if u.HasAdminScope() {
			t.Error("HasAdminScope() = true for admin:read/admin:write, want false (requires exact 'admin')")
		}
	})
}
