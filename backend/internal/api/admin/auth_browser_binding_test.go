package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Issue #738 — login CSRF / forced session fixation.
//
// The table is over the STATES OF THE BINDING rather than over one crafted
// attack, because every one of these is a way the check can be defeated and
// they fail for different reasons: no cookie at all is the attacker's browser,
// a wrong cookie is a guess, and an empty stored hash is a state entry written
// before the binding existed.

func ctxWithCookie(value string) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/callback?code=x&state=y", nil)
	if value != "" {
		c.Request.AddCookie(&http.Cookie{Name: loginBindingCookie, Value: value})
	}
	return c
}

func TestLoginBindingMatches(t *testing.T) {
	secret, hash, err := newLoginBinding()
	if err != nil {
		t.Fatalf("newLoginBinding: %v", err)
	}
	_, otherHash, _ := newLoginBinding()

	tests := []struct {
		name       string
		cookie     string
		storedHash string
		want       bool
	}{
		{"the browser that started the login", secret, hash, true},
		{"no cookie at all — the attacker's browser", "", hash, false},
		{"a cookie that does not match", "not-the-secret", hash, false},
		{"the right secret against someone else's hash", secret, otherHash, false},
		// Fails closed. A state entry written before this binding existed has no
		// expectation recorded, and treating that as "anything matches" is how a
		// check like this becomes decorative during a rolling deploy.
		{"empty stored hash — no expectation recorded", secret, "", false},
		{"empty stored hash and no cookie", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loginBindingMatches(ctxWithCookie(tt.cookie), tt.storedHash); got != tt.want {
				t.Errorf("loginBindingMatches(cookie=%q, stored=%q) = %v, want %v",
					tt.cookie, tt.storedHash, got, tt.want)
			}
		})
	}
}

// The stored value must be a hash, not the secret: read access to the state
// store must not yield a forgeable cookie.
func TestNewLoginBindingStoresAHashNotTheSecret(t *testing.T) {
	secret, hash, err := newLoginBinding()
	if err != nil {
		t.Fatalf("newLoginBinding: %v", err)
	}
	if secret == "" || hash == "" {
		t.Fatal("both the secret and its hash must be non-empty")
	}
	if secret == hash {
		t.Fatal("the stored value is the secret itself; a state-store read would forge the cookie")
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64 hex chars (sha256)", len(hash))
	}
}

// Two logins must not share a binding, or one user's callback completes
// another's login.
func TestNewLoginBindingIsUniquePerCall(t *testing.T) {
	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		secret, hash, err := newLoginBinding()
		if err != nil {
			t.Fatalf("newLoginBinding: %v", err)
		}
		if seen[secret] || seen[hash] {
			t.Fatal("newLoginBinding repeated a value")
		}
		seen[secret], seen[hash] = true, true
	}
}

// The cookie has to survive the IdP's top-level redirect back to the callback,
// and must not be readable by script or ride every API request.
func TestIssueLoginBindingCookieAttributes(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/login", nil)
	issueLoginBinding(c, "the-secret")

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected exactly one cookie, got %d", len(cookies))
	}
	got := cookies[0]
	if got.Name != loginBindingCookie {
		t.Errorf("name = %q, want %q", got.Name, loginBindingCookie)
	}
	if !got.HttpOnly {
		t.Error("must be HttpOnly — it is only ever read server-side")
	}
	if !got.Secure {
		t.Error("must be Secure")
	}
	// Strict would be dropped on the IdP's cross-site top-level redirect, which
	// breaks every login — the failure that gets a check like this deleted.
	if got.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax so it survives the IdP redirect", got.SameSite)
	}
	if got.Path != loginBindingPath {
		t.Errorf("Path = %q, want %q — it should not ride every API request", got.Path, loginBindingPath)
	}
}
