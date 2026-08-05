package credscope

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
)

func testContext(authMethod string, sessionScopes []string, key *models.APIKey) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if authMethod != "" {
		c.Set("auth_method", authMethod)
	}
	if sessionScopes != nil {
		c.Set("scopes", sessionScopes)
	}
	if key != nil {
		c.Set("api_key", key)
	}
	return c
}

func key(scopes ...string) *models.APIKey {
	owner := "user-1"
	return &models.APIKey{UserID: &owner, OrganizationID: "org-1", Scopes: scopes}
}

// TestBound covers the scope lattice in both directions. The wildcard rows are
// the reason Bound is not a set intersection: "admin" and a write scope each
// stand in for scopes they do not literally contain, so a literal intersection
// would return the empty set and deny a request both sides plainly permit.
func TestBound(t *testing.T) {
	tests := []struct {
		name        string
		userDerived []string
		presented   *models.APIKey
		// badPrincipal sets an api_key context value of the wrong type.
		badPrincipal bool
		want         []string
	}{
		{
			name:        "interactive session keeps the user-derived ceiling",
			userDerived: []string{"admin"},
			presented:   nil,
			want:        []string{"admin"},
		},
		{
			name:        "narrow key under an admin owner keeps only what it holds",
			userDerived: []string{"admin"},
			presented:   key("modules:read"),
			want:        []string{"modules:read"},
		},
		{
			name:        "admin key under a narrow owner keeps only what the owner grants",
			userDerived: []string{"modules:read"},
			presented:   key("admin"),
			want:        []string{"modules:read"},
		},
		{
			name:        "admin on both sides survives",
			userDerived: []string{"admin"},
			presented:   key("admin"),
			want:        []string{"admin"},
		},
		{
			name:        "write does not survive a read-only key, but read does",
			userDerived: []string{"modules:write"},
			presented:   key("modules:read"),
			want:        []string{"modules:read"},
		},
		{
			name:        "disjoint sets yield nothing",
			userDerived: []string{"modules:read"},
			presented:   key("providers:read"),
			want:        []string{},
		},
		{
			name:        "overlap is kept, non-overlap is dropped",
			userDerived: []string{"modules:read", "providers:write"},
			presented:   key("modules:read", "scm:manage"),
			want:        []string{"modules:read"},
		},
		{
			name:         "an uninterpretable key principal grants nothing",
			userDerived:  []string{"admin"},
			badPrincipal: true,
			want:         []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c *gin.Context
			switch {
			case tt.badPrincipal:
				c, _ = gin.CreateTestContext(httptest.NewRecorder())
				c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
				c.Set("api_key", "not-a-key")
			case tt.presented == nil:
				c = testContext("jwt", tt.userDerived, nil)
			default:
				c = testContext("api_key", tt.presented.Scopes, tt.presented)
			}

			got := Bound(c, tt.userDerived)
			sort.Strings(got)
			want := append([]string{}, tt.want...)
			sort.Strings(want)
			if len(got) == 0 && len(want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Bound = %v, want %v", got, want)
			}
		})
	}
}

// TestPresentedPrefersDerivedScopes proves Bound reads the NARROWER of the two
// scope sets available for a key: AuthMiddleware already intersected the row's
// frozen scopes with the owner's current role template (issue #732), so the
// context set — not the stored row — is authoritative.
func TestPresentedPrefersDerivedScopes(t *testing.T) {
	c := testContext("api_key", []string{"modules:read"}, key("modules:read", "providers:write"))
	got, isKey := Presented(c)
	if !isKey {
		t.Fatal("Presented did not report an API-key principal")
	}
	if !reflect.DeepEqual(got, []string{"modules:read"}) {
		t.Fatalf("Presented = %v, want the derived context scopes [modules:read]", got)
	}
}

// TestPresentedFallsBackToStoredScopes covers the wiring where a key is in
// context but no derived scope set is (unit tests, and any middleware that sets
// only the principal).
func TestPresentedFallsBackToStoredScopes(t *testing.T) {
	c := testContext("api_key", nil, key("modules:read"))
	got, isKey := Presented(c)
	if !isKey || !reflect.DeepEqual(got, []string{"modules:read"}) {
		t.Fatalf("Presented = %v, %v; want [modules:read], true", got, isKey)
	}
}

func TestInteractive(t *testing.T) {
	tests := []struct {
		authMethod string
		want       bool
	}{
		{"jwt", true},
		{"jwt_cookie", true},
		{"api_key", false},
		{"mtls", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run("auth_method="+tt.authMethod, func(t *testing.T) {
			if got := Interactive(testContext(tt.authMethod, nil, nil)); got != tt.want {
				t.Fatalf("Interactive = %v, want %v", got, tt.want)
			}
		})
	}
}
