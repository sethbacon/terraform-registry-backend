package middleware

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/config"
)

// BinaryMirrorAuthMiddleware returns a Gin handler that enforces access control on the
// /terraform/binaries route group according to cfg.Auth:
//
//   - "none"      — pass-through; no checks performed (default / existing behaviour).
//   - "allowlist" — only requests whose client IP falls within one of the configured CIDR
//     ranges are allowed; everything else receives 403.
//   - "mtls"      — requires a verified TLS client certificate on the connection; requests
//     without one receive 403.
//
// Any unrecognised Auth value is treated as "none" to avoid accidentally locking out
// operators who upgrade with a misconfigured value.
func BinaryMirrorAuthMiddleware(cfg config.BinaryMirrorConfig) gin.HandlerFunc {
	switch cfg.Auth {
	case "allowlist":
		return binaryMirrorAllowlistMiddleware(cfg.Allowlist)
	case "mtls":
		return binaryMirrorMTLSMiddleware()
	default:
		// "none" or any unrecognised value — pass through.
		return func(c *gin.Context) { c.Next() }
	}
}

// binaryMirrorAllowlistMiddleware builds parsed CIDR nets once at startup, then checks
// each request's client IP against them.
func binaryMirrorAllowlistMiddleware(cidrs []string) gin.HandlerFunc {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}

	return func(c *gin.Context) {
		clientIP := net.ParseIP(c.ClientIP())
		if clientIP == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		for _, ipNet := range nets {
			if ipNet.Contains(clientIP) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	}
}

// binaryMirrorMTLSMiddleware requires at least one verified TLS client certificate to be
// present on the connection. When TLS termination is done upstream (e.g. a load balancer)
// this check will always pass because c.Request.TLS will be nil — operators relying on
// mTLS termination must enforce the requirement at the load-balancer level.
func binaryMirrorMTLSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS == nil || len(c.Request.TLS.VerifiedChains) == 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "client certificate required"})
			return
		}
		c.Next()
	}
}
