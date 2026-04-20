// Package middleware — csrf.go implements double-submit cookie CSRF protection.
//
// When cookie-based authentication is active (B2.4), the browser automatically
// includes the auth cookie on every request. This opens the door to cross-site
// request forgery. The double-submit pattern mitigates this by:
//
//  1. Setting a non-HttpOnly "tfr_csrf" cookie containing a random token.
//  2. Requiring mutating requests (POST, PUT, PATCH, DELETE) to echo the same
//     token back in the X-CSRF-Token header.
//
// Because an attacker on a different origin cannot read the cookie value (SameSite
// + secure flag), they cannot construct a valid X-CSRF-Token header.
//
// Safe methods (GET, HEAD, OPTIONS) are exempt because they must be side-effect-free
// per HTTP semantics.
package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// CSRFCookieName is the non-HttpOnly cookie readable by the frontend.
	CSRFCookieName = "tfr_csrf"

	// CSRFHeaderName is the header the frontend must echo the token in.
	CSRFHeaderName = "X-CSRF-Token"

	// csrfTokenBytes is the length of the raw random token (32 bytes → 44-char base64).
	csrfTokenBytes = 32
)

// generateCSRFToken creates a cryptographically random base64url token.
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SetCSRFCookie writes (or refreshes) the CSRF double-submit cookie.
// Call this when issuing or refreshing the auth cookie so the frontend always
// has a matching token to include in mutating requests.
func SetCSRFCookie(w http.ResponseWriter, secure bool) (string, error) {
	token, err := generateCSRFToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   86400, // match auth cookie lifetime
		Secure:   secure,
		HttpOnly: false, // must be readable by JS
		SameSite: http.SameSiteLaxMode,
	})
	return token, nil
}

// ClearCSRFCookie removes the CSRF cookie (e.g. on logout).
func ClearCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
}

// CSRFMiddleware enforces the double-submit cookie pattern on mutating HTTP methods.
// Safe methods (GET, HEAD, OPTIONS) pass through unconditionally.
// Requests authenticated via API key (Authorization: Bearer <api_key>) are exempt
// because API keys are not sent automatically by the browser — they are only used
// by programmatic clients (Terraform CLI, CI scripts) that are not vulnerable to CSRF.
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Safe methods are exempt — they must be side-effect-free.
		method := strings.ToUpper(c.Request.Method)
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			c.Next()
			return
		}

		// API-key-authenticated requests are exempt. The auth middleware sets
		// "auth_method" = "api_key" when authentication succeeded via API key.
		// API keys are never sent automatically by the browser, so CSRF is not
		// a concern for those callers.
		if authMethod, exists := c.Get("auth_method"); exists {
			if am, ok := authMethod.(string); ok && am == "api_key" {
				c.Next()
				return
			}
		}

		// If the request was authenticated via cookie (auth_method == "jwt_cookie"),
		// enforce CSRF. If authenticated via Authorization header JWT, exempt as well
		// since that requires explicit JS action.
		if authMethod, exists := c.Get("auth_method"); exists {
			if am, ok := authMethod.(string); ok && am == "jwt" {
				// Bearer header JWT — not auto-sent by browser, exempt from CSRF.
				c.Next()
				return
			}
		}

		// At this point the request is cookie-authenticated. Validate CSRF token.
		cookieToken, err := c.Cookie(CSRFCookieName)
		if err != nil || cookieToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "CSRF cookie missing",
			})
			return
		}

		headerToken := c.GetHeader(CSRFHeaderName)
		if headerToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "CSRF token header missing",
			})
			return
		}

		// Constant-time comparison to prevent timing attacks.
		if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "CSRF token mismatch",
			})
			return
		}

		c.Next()
	}
}
