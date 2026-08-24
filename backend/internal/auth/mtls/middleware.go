package mtls

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
)

// AuthMiddleware creates Gin middleware that authenticates requests using
// mTLS client certificates. If a verified client cert is present and maps
// to configured scopes, the scopes are set in the Gin context.
// This middleware is additive — it does NOT reject requests without certs.
// It only applies when the TLS handshake has already verified the cert chain.
//
// Register this middleware globally, before the per-route AuthMiddleware /
// OptionalAuthMiddleware groups (see router.go), so the identity/scopes it
// sets are already in the Gin context by the time those run. AuthMiddleware
// treats auth_method=="mtls" as satisfying the "credentials present" check
// even with no bearer token, so an mTLS-authenticated request reaches the
// RBAC layer normally.
//
// THE SCOPES PUBLISHED HERE ARE CARRIER-RESOLVED, NOT AS CONFIGURED (#876).
//
// A subject→scope mapping is a claim written in a config file. Before this,
// that claim was published verbatim, so `scopes: ["admin"]` made the caller a
// platform administrator with no grant record, no audit entry, and no
// revocation short of editing configuration and restarting — while every other
// credential class had been brought under the carrier by #874 (sessions through
// SessionScopes, API keys stripped by KeyScopes). mTLS was the one that kept
// its own answer to "who is a platform administrator?".
//
// Now a mapping that names a user is resolved through the carrier exactly as a
// session is, so `admin` holds only while that user holds a carrier row and
// stops holding the moment the row is revoked. A mapping that names no user
// cannot reach `admin` at all: NewProvider refuses to build one at startup, and
// the publish path below strips it anyway.
func AuthMiddleware(p *Provider, carrier *platformadmin.Carrier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if p == nil {
			c.Next()
			return
		}

		// Only inspect VerifiedChains, not PeerCertificates: VerifiedChains is
		// populated by Go's TLS stack only after the presented certificate has
		// been chain-verified against the server's ClientCAs (wired in
		// cmd/server/main.go via ClientAuth=tls.VerifyClientCertIfGiven).
		// PeerCertificates would include the raw certificate the client
		// presented even when no ClientCAs are configured or verification
		// failed, which would let an unverified/self-signed cert be trusted
		// for subject→scope mapping (issue #559 finding [3]).
		if c.Request.TLS == nil || len(c.Request.TLS.VerifiedChains) == 0 || len(c.Request.TLS.VerifiedChains[0]) == 0 {
			c.Next()
			return
		}

		cert := c.Request.TLS.VerifiedChains[0][0]
		subject, scopes, userID, err := p.Authenticate(cert)
		if err != nil {
			slog.Debug("mTLS auth: no mapping for client cert", "cn", cert.Subject.CommonName, "error", err)
			c.Next()
			return
		}

		effective, status, msg := resolveScopes(c, carrier, userID, scopes)
		if status != 0 {
			// An authority question that did not resolve is not a completed
			// "no". Aborting with 500 rather than continuing unelevated matches
			// middleware.AuthMiddleware's treatment of the same failure: a
			// silent downgrade would take the admin surface away from an
			// administrator during exactly the incident they need it in, with
			// nothing in the response saying why.
			c.AbortWithStatusJSON(status, gin.H{"error": msg})
			return
		}

		// Set auth context for downstream middleware/handlers
		c.Set("auth_method", "mtls")
		c.Set("mtls_subject", subject)
		c.Set("scopes", effective)

		// Published under its OWN key rather than as "user_id" — deliberately.
		//
		// 36 non-test sites read "user_id", and some of them authorize with it
		// (namespace_authz.go:487 among them). Setting it here would make an
		// mTLS caller indistinguishable from a signed-in user across all of
		// them, which is a second, wider change than binding a certificate to a
		// carrier row, and is the kind of undesigned change #874 declined to
		// carry. The binding is recorded so it can be audited and so this
		// decision can be revisited on its own evidence.
		if userID != "" {
			c.Set("mtls_user_id", userID)
		}

		slog.Info("mTLS auth: client authenticated",
			"subject", subject, "user_id", userID, "scopes", effective)
		c.Next()
	}
}

// resolveScopes turns a mapping's CONFIGURED scopes into the effective ones.
//
// Two paths, and neither can publish `admin` on the strength of the config
// alone:
//
//   - the mapping NAMES A USER — the scopes go through the same
//     Carrier.SessionScopes a JWT session uses, so `admin` survives only while
//     that user holds a carrier row, and revoking the row disarms the
//     certificate on the next request rather than at the next restart;
//   - the mapping names NO user — KeyScopes, the API-key treatment: `admin`
//     removed, always. NewProvider already refuses to build such a mapping with
//     `admin` in it, so this is the second of two locks on the same door. It is
//     here because the first one guards a construction path and this one guards
//     the publish, and only the publish is what the RBAC layer reads.
//
// A nil carrier degrades to stripping rather than to trusting.
func resolveScopes(c *gin.Context, carrier *platformadmin.Carrier, userID string, scopes []string) ([]string, int, string) {
	if carrier == nil || userID == "" {
		return platformadmin.KeyScopes(scopes), 0, ""
	}
	effective, err := carrier.SessionScopes(c.Request.Context(), userID, scopes)
	if err != nil {
		return effective, http.StatusInternalServerError, "Auth check failed"
	}
	return effective, 0, ""
}

// RequireMTLS creates middleware that rejects requests without a valid mTLS
// client certificate. Use this for endpoints that MUST be authenticated via
// client certs (e.g., machine-to-machine only routes).
func RequireMTLS() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, exists := c.Get("mtls_subject"); !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "mTLS client certificate required",
			})
			return
		}
		c.Next()
	}
}
