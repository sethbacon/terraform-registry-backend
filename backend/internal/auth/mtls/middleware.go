package mtls

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
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
func AuthMiddleware(p *Provider) gin.HandlerFunc {
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
		subject, scopes, err := p.Authenticate(cert)
		if err != nil {
			slog.Debug("mTLS auth: no mapping for client cert", "cn", cert.Subject.CommonName, "error", err)
			c.Next()
			return
		}

		// Set auth context for downstream middleware/handlers
		c.Set("auth_method", "mtls")
		c.Set("mtls_subject", subject)
		c.Set("scopes", scopes)

		slog.Info("mTLS auth: client authenticated", "subject", subject, "scopes", scopes)
		c.Next()
	}
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
