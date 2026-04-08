// security.go provides Gin middleware that injects protective HTTP response headers including
// Content-Security-Policy, HSTS, X-Frame-Options, and other security directives.
package middleware

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

// SecurityHeadersConfig holds configuration for security headers
type SecurityHeadersConfig struct {
	// EnableHSTS enables HTTP Strict Transport Security
	EnableHSTS bool
	// HSTSMaxAge is the max-age value for HSTS in seconds (default: 1 year)
	HSTSMaxAge int
	// HSTSIncludeSubdomains includes subdomains in HSTS
	HSTSIncludeSubdomains bool
	// HSTSPreload enables HSTS preloading
	HSTSPreload bool
	// EnableFrameOptions enables X-Frame-Options header
	EnableFrameOptions bool
	// FrameOptionsValue is the value for X-Frame-Options (DENY, SAMEORIGIN)
	FrameOptionsValue string
	// EnableContentTypeOptions enables X-Content-Type-Options: nosniff
	EnableContentTypeOptions bool
	// EnableXSSProtection enables X-XSS-Protection header
	EnableXSSProtection bool
	// ContentSecurityPolicy is the CSP header value
	ContentSecurityPolicy string
	// ReferrerPolicy is the Referrer-Policy header value
	ReferrerPolicy string
	// PermissionsPolicy is the Permissions-Policy header value
	PermissionsPolicy string
}

// DefaultSecurityHeadersConfig returns sensible security header defaults
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		EnableHSTS:               true,
		HSTSMaxAge:               31536000, // 1 year
		HSTSIncludeSubdomains:    true,
		HSTSPreload:              false, // Requires careful consideration
		EnableFrameOptions:       true,
		FrameOptionsValue:        "DENY",
		EnableContentTypeOptions: true,
		EnableXSSProtection:      true,
		ContentSecurityPolicy:    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'",
		ReferrerPolicy:           "strict-origin-when-cross-origin",
		PermissionsPolicy:        "geolocation=(), microphone=(), camera=()",
	}
}

// APISecurityHeadersConfig returns security headers suitable for API endpoints
func APISecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		EnableHSTS:               true,
		HSTSMaxAge:               31536000,
		HSTSIncludeSubdomains:    true,
		HSTSPreload:              false,
		EnableFrameOptions:       true,
		FrameOptionsValue:        "DENY",
		EnableContentTypeOptions: true,
		EnableXSSProtection:      false, // Not relevant for JSON APIs
		ContentSecurityPolicy:    "default-src 'none'; frame-ancestors 'none'",
		ReferrerPolicy:           "no-referrer",
		PermissionsPolicy:        "",
	}
}

// SecurityHeadersMiddleware adds security headers to all responses
func SecurityHeadersMiddleware(config SecurityHeadersConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// HTTP Strict Transport Security — only send over TLS connections
		isTLS := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
		if config.EnableHSTS && isTLS {
			hstsValue := "max-age=" + strconv.Itoa(config.HSTSMaxAge)
			if config.HSTSIncludeSubdomains {
				hstsValue += "; includeSubDomains"
			}
			if config.HSTSPreload {
				hstsValue += "; preload"
			}
			c.Header("Strict-Transport-Security", hstsValue)
		}

		// X-Frame-Options
		if config.EnableFrameOptions && config.FrameOptionsValue != "" {
			c.Header("X-Frame-Options", config.FrameOptionsValue)
		}

		// X-Content-Type-Options
		if config.EnableContentTypeOptions {
			c.Header("X-Content-Type-Options", "nosniff")
		}

		// X-XSS-Protection (legacy, but still useful for older browsers)
		if config.EnableXSSProtection {
			c.Header("X-XSS-Protection", "1; mode=block")
		}

		// Content-Security-Policy
		if config.ContentSecurityPolicy != "" {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
		}

		// Referrer-Policy
		if config.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", config.ReferrerPolicy)
		}

		// Permissions-Policy (formerly Feature-Policy)
		if config.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", config.PermissionsPolicy)
		}

		// Additional security headers
		c.Header("X-Permitted-Cross-Domain-Policies", "none")
		c.Header("Cross-Origin-Embedder-Policy", "require-corp")
		c.Header("Cross-Origin-Opener-Policy", "same-origin")
		c.Header("Cross-Origin-Resource-Policy", "same-origin")

		c.Next()
	}
}
