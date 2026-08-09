package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Login-CSRF binding for the OAuth/OIDC/SAML flows (issue #738).
//
// The `state` parameter alone proves only that SOME login was started on this
// server -- it is stored server-side keyed by itself, so any holder of a valid
// state string can complete the flow from any browser. That makes the standard
// login-CSRF attack work: the attacker starts a login, authenticates at the IdP
// as themselves, captures code+state, and induces the victim's browser to load
// the callback as a plain top-level GET. SameSite=Lax does not block that, so
// the victim is issued a session for the ATTACKER's identity.
//
// In a registry that is not cosmetic. The victim may then publish a module,
// upload a provider with signing material, link an SCM provider, or mint an API
// key -- all inside an account the attacker controls and later collects.
//
// The fix is the one the OAuth 2.0 Security BCP prescribes: bind `state` to a
// value only the initiating browser holds. `/auth/login` issues a random secret
// in an HttpOnly cookie and stores only its SHA-256 in the session state; the
// callback recomputes and compares. A browser that did not start the login has
// no cookie, so the callback refuses.
//
// The stored value is a HASH, not the secret: whoever can read the state store
// -- a Redis operator, a backup, a memory dump -- still cannot forge the cookie.
// That is the same reasoning as storing password hashes, applied to a value with
// a five-minute life.

const (
	// loginBindingCookie is scoped to the auth path rather than "/": it is only
	// ever read at the callback, and a cookie that rides every request to the
	// API is one more thing that can leak in a log or a Referer.
	loginBindingCookie = "tfr_login_binding"
	loginBindingPath   = "/api/v1/auth"
	// Matches the callback's own 5-minute state freshness check. A binding that
	// outlives the state it binds protects nothing.
	loginBindingMaxAge = 300
)

// newLoginBinding returns a fresh browser secret and the hash to persist.
func newLoginBinding() (secret string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(secret))
	return secret, hex.EncodeToString(sum[:]), nil
}

// issueLoginBinding sets the browser-bound cookie for a login just started.
//
// Secure and HttpOnly unconditionally: this is only read server-side, and a
// deployment serving the callback over plain HTTP has a larger problem than
// this cookie. SameSite=Lax because the callback arrives as a top-level
// navigation from the IdP -- Strict would drop the cookie and break every login,
// which is precisely the mistake that makes people delete the check.
func issueLoginBinding(c *gin.Context, secret string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     loginBindingCookie,
		Value:    secret,
		Path:     loginBindingPath,
		MaxAge:   loginBindingMaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearLoginBinding expires the cookie once the callback has consumed it. The
// binding is single-use like the state it accompanies.
func clearLoginBinding(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     loginBindingCookie,
		Value:    "",
		Path:     loginBindingPath,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// loginBindingMatches reports whether this request's cookie matches the hash
// stored with the login state.
//
// FAILS CLOSED on an empty stored hash. That is the case for a state entry
// written before this binding existed, and treating "no expectation recorded"
// as "anything matches" is how a check like this becomes decorative during a
// rolling deploy. The cost is that logins already in flight across the upgrade
// must be retried, which is a five-minute window and the same behaviour the
// nonce/PKCE bindings already have.
func loginBindingMatches(c *gin.Context, storedHash string) bool {
	if storedHash == "" {
		return false
	}
	cookie, err := c.Request.Cookie(loginBindingCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	sum := sha256.Sum256([]byte(cookie.Value))
	// Constant time: the comparison is against a value an attacker supplies and
	// can iterate on, so it should not leak a prefix length through timing.
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(storedHash)) == 1
}
