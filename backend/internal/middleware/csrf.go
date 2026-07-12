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
// Bearer-authenticated requests are NOT unconditionally exempt: a browser can
// carry a Bearer token too (the frontend historically did exactly that), which
// would make the control bypassable-by-construction. Instead, browser context is
// detected via the Origin header (Referer as fallback) and browser-context Bearer
// mutations must come from an allowed origin (server public URL / base URL /
// configured CORS origins). Requests with no Origin/Referer (terraform CLI, curl,
// CI scripts) remain exempt because a CSRF attack always executes in a browser,
// and browsers always attach Origin to cross-origin mutating requests.
//
// Safe methods (GET, HEAD, OPTIONS) are exempt because they must be side-effect-free
// per HTTP semantics.
package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
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
	// #nosec G124 -- double-submit CSRF cookie must be readable by JS (HttpOnly=false by design)
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
	// #nosec G124 -- double-submit CSRF cookie must be readable by JS (HttpOnly=false by design)
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

// canonicalOrigin reduces a URL or Origin-header value to a comparable
// "scheme://host" form: lowercased, with default ports (http:80, https:443)
// stripped. It returns "" for anything that does not parse to a scheme+host
// (including the literal "null" origin browsers send for opaque contexts).
func canonicalOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch scheme {
	case "http":
		host = strings.TrimSuffix(host, ":80")
	case "https":
		host = strings.TrimSuffix(host, ":443")
	}
	return scheme + "://" + host
}

// csrfOriginAllowlist builds the set of browser origins allowed to send
// Bearer-authenticated mutations. It reuses the deployment's existing sources
// of truth rather than introducing a new knob: server.public_url,
// server.base_url, and security.cors.allowed_origins. A CORS wildcard ("*")
// is deliberately NOT honored here — it does not identify this deployment's
// own origins, and honoring it would disable the check entirely.
func csrfOriginAllowlist(cfg *config.Config) map[string]struct{} {
	allowed := make(map[string]struct{})
	if cfg == nil {
		return allowed
	}
	candidates := []string{cfg.Server.GetPublicURL(), cfg.Server.BaseURL}
	candidates = append(candidates, cfg.Security.CORS.AllowedOrigins...)
	for _, candidate := range candidates {
		if candidate == "*" {
			continue
		}
		if origin := canonicalOrigin(candidate); origin != "" {
			allowed[origin] = struct{}{}
		}
	}
	return allowed
}

// requestOrigin returns the canonical browser origin of a request: the Origin
// header when present, falling back to the Referer's scheme+host. An empty
// return means the request carried neither — i.e. a non-browser client.
func requestOrigin(c *gin.Context) string {
	if origin := c.GetHeader("Origin"); origin != "" {
		// "null" (sandboxed/opaque contexts) canonicalizes to "" — treat it as
		// browser context that can never match the allowlist, not as absent.
		if canonical := canonicalOrigin(origin); canonical != "" {
			return canonical
		}
		return "null"
	}
	if referer := c.GetHeader("Referer"); referer != "" {
		if canonical := canonicalOrigin(referer); canonical != "" {
			return canonical
		}
		return "null"
	}
	return ""
}

// CSRFMiddleware enforces the double-submit cookie pattern on mutating HTTP methods.
// Safe methods (GET, HEAD, OPTIONS) pass through unconditionally.
// Requests authenticated via API key (Authorization: Bearer <api_key>) are exempt
// because API keys are not sent automatically by the browser — they are only used
// by programmatic clients (Terraform CLI, CI scripts) that are not vulnerable to CSRF.
//
// Enforcement matrix for mutating methods:
//
//	auth_method  Origin/Referer  enforcement
//	api_key      any             exempt (API keys are never auto-sent by browsers)
//	jwt (Bearer) absent          exempt (programmatic client: CLI, CI, curl)
//	jwt (Bearer) present         origin allowlist — 403 unless scheme+host matches
//	                             server public/base URL or a configured CORS origin
//	jwt_cookie   any             double-submit token validation
//
// Bearer browser clients may not hold the tfr_csrf cookie (they never went
// through the cookie-issuing login flow), so the double-submit check cannot
// apply; the origin allowlist provides the equivalent cross-site guarantee.
func CSRFMiddleware(cfg *config.Config) gin.HandlerFunc {
	allowedOrigins := csrfOriginAllowlist(cfg)
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

		// Bearer header JWT (auth_method == "jwt"). Historically exempted as
		// "programmatic", but a browser can carry a Bearer token too. Detect
		// browser context via Origin (Referer fallback): no Origin/Referer means
		// a non-browser client and stays exempt; a browser origin must match the
		// deployment's own origins or the request is rejected.
		if authMethod, exists := c.Get("auth_method"); exists {
			if am, ok := authMethod.(string); ok && am == "jwt" {
				origin := requestOrigin(c)
				if origin == "" {
					// No browser context — programmatic client, exempt.
					c.Next()
					return
				}
				if _, ok := allowedOrigins[origin]; !ok {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"error": "request origin not allowed",
					})
					return
				}
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
