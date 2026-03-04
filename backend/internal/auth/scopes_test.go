package auth

import "testing"

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []string
		wantErr bool
	}{
		{"empty list", []string{}, false},
		{"single valid scope", []string{"modules:read"}, false},
		{"multiple valid scopes", []string{"modules:read", "providers:write", "admin"}, false},
		{"all defined scopes", func() []string {
			s := make([]string, 0, len(AllScopes()))
			for _, sc := range AllScopes() {
				s = append(s, string(sc))
			}
			return s
		}(), false},
		{"invalid scope", []string{"not:a:scope"}, true},
		{"mixed valid and invalid", []string{"modules:read", "invalid"}, true},
		{"empty string scope", []string{""}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScopes(tt.scopes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScopes(%v) error = %v, wantErr %v", tt.scopes, err, tt.wantErr)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		name       string
		userScopes []string
		required   Scope
		want       bool
	}{
		// Exact match
		{"exact match modules:read", []string{"modules:read"}, ScopeModulesRead, true},
		{"exact match admin", []string{"admin"}, ScopeAdmin, true},
		// Admin wildcard grants everything
		{"admin grants modules:read", []string{"admin"}, ScopeModulesRead, true},
		{"admin grants providers:write", []string{"admin"}, ScopeProvidersWrite, true},
		{"admin grants mirrors:manage", []string{"admin"}, ScopeMirrorsManage, true},
		{"admin grants users:read", []string{"admin"}, ScopeUsersRead, true},
		// Write implies read
		{"modules:write implies modules:read", []string{"modules:write"}, ScopeModulesRead, true},
		{"providers:write implies providers:read", []string{"providers:write"}, ScopeProvidersRead, true},
		{"users:write implies users:read", []string{"users:write"}, ScopeUsersRead, true},
		{"mirrors:manage implies mirrors:read", []string{"mirrors:manage"}, ScopeMirrorsRead, true},
		{"organizations:write implies organizations:read", []string{"organizations:write"}, ScopeOrganizationsRead, true},
		{"scm:manage implies scm:read", []string{"scm:manage"}, ScopeSCMRead, true},
		// Write does NOT imply unrelated read
		{"modules:write does not imply providers:read", []string{"modules:write"}, ScopeProvidersRead, false},
		// No match
		{"no scopes", []string{}, ScopeModulesRead, false},
		{"wrong scope", []string{"providers:read"}, ScopeModulesRead, false},
		{"read does not imply write", []string{"modules:read"}, ScopeModulesWrite, false},
		// Multiple scopes, one matches
		{"one of many matches", []string{"providers:read", "modules:read"}, ScopeModulesRead, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasScope(tt.userScopes, tt.required)
			if got != tt.want {
				t.Errorf("HasScope(%v, %q) = %v, want %v", tt.userScopes, tt.required, got, tt.want)
			}
		})
	}
}

func TestHasAnyScope(t *testing.T) {
	tests := []struct {
		name           string
		userScopes     []string
		requiredScopes []Scope
		want           bool
	}{
		{"matches first", []string{"modules:read"}, []Scope{ScopeModulesRead, ScopeProvidersRead}, true},
		{"matches second", []string{"providers:read"}, []Scope{ScopeModulesRead, ScopeProvidersRead}, true},
		{"matches none", []string{"audit:read"}, []Scope{ScopeModulesRead, ScopeProvidersRead}, false},
		{"empty required", []string{"modules:read"}, []Scope{}, false},
		{"empty user scopes", []string{}, []Scope{ScopeModulesRead}, false},
		{"admin matches any", []string{"admin"}, []Scope{ScopeUsersWrite, ScopeMirrorsManage}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasAnyScope(tt.userScopes, tt.requiredScopes)
			if got != tt.want {
				t.Errorf("HasAnyScope(%v, %v) = %v, want %v", tt.userScopes, tt.requiredScopes, got, tt.want)
			}
		})
	}
}

func TestHasAllScopes(t *testing.T) {
	tests := []struct {
		name           string
		userScopes     []string
		requiredScopes []Scope
		want           bool
	}{
		{"has all", []string{"modules:read", "providers:read"}, []Scope{ScopeModulesRead, ScopeProvidersRead}, true},
		{"missing one", []string{"modules:read"}, []Scope{ScopeModulesRead, ScopeProvidersRead}, false},
		{"empty required", []string{"modules:read"}, []Scope{}, true},
		{"empty user no requirements", []string{}, []Scope{}, true},
		{"empty user has requirements", []string{}, []Scope{ScopeModulesRead}, false},
		{"admin has all", []string{"admin"}, []Scope{ScopeModulesRead, ScopeProvidersWrite, ScopeMirrorsManage}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasAllScopes(tt.userScopes, tt.requiredScopes)
			if got != tt.want {
				t.Errorf("HasAllScopes(%v, %v) = %v, want %v", tt.userScopes, tt.requiredScopes, got, tt.want)
			}
		})
	}
}

func TestValidateScopeString(t *testing.T) {
	tests := []struct {
		scope   string
		wantErr bool
	}{
		{"modules:read", false},
		{"admin", false},
		{"audit:read", false},
		{"invalid", true},
		{"", true},
		{"modules:delete", true},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			err := ValidateScopeString(tt.scope)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScopeString(%q) error = %v, wantErr %v", tt.scope, err, tt.wantErr)
			}
		})
	}
}

func TestGetDefaultScopes(t *testing.T) {
	scopes := GetDefaultScopes()
	if len(scopes) == 0 {
		t.Fatal("GetDefaultScopes() returned empty slice")
	}
	// All returned scopes must be valid
	if err := ValidateScopes(scopes); err != nil {
		t.Errorf("GetDefaultScopes() returned invalid scopes: %v", err)
	}
}

func TestGetAdminScopes(t *testing.T) {
	scopes := GetAdminScopes()
	if len(scopes) == 0 {
		t.Fatal("GetAdminScopes() returned empty slice")
	}
	// Must contain at least as many scopes as AllScopes()
	if len(scopes) != len(AllScopes()) {
		t.Errorf("GetAdminScopes() len = %d, want %d", len(scopes), len(AllScopes()))
	}
	if err := ValidateScopes(scopes); err != nil {
		t.Errorf("GetAdminScopes() returned invalid scopes: %v", err)
	}
}

func TestAllScopesUnique(t *testing.T) {
	seen := make(map[Scope]bool)
	for _, sc := range AllScopes() {
		if seen[sc] {
			t.Errorf("duplicate scope in AllScopes(): %q", sc)
		}
		seen[sc] = true
	}
}
