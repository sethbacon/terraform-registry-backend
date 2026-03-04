package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// RequestIDHeader is the canonical HTTP header used to propagate the request identifier.
	RequestIDHeader = "X-Request-ID"

	// RequestIDKey is the gin.Context key under which the request ID string is stored so
	// that handlers and other middleware can retrieve it without reading the response header.
	RequestIDKey = "request_id"
)

// RequestIDMiddleware returns a Gin handler that ensures every request carries a unique
// identifier propagated as an X-Request-ID HTTP header.
//
// Behaviour:
//   - If the inbound request already carries an X-Request-ID header (set by an upstream
//     load balancer, API gateway, or caller), its value is reused unchanged.
//   - Otherwise a new UUID v4 is generated for the request.
//
// The identifier is stored in gin.Context under RequestIDKey so that handlers and
// downstream middleware can read it without parsing HTTP headers:
//
//	id, _ := c.Get(middleware.RequestIDKey)
//
// The identifier is also echoed back in the response X-Request-ID header so clients
// can correlate their request with server-side structured log entries.
//
// Register this middleware as early as possible so all downstream logging includes the ID:
//
//	router.Use(gin.Recovery())
//	router.Use(RequestIDMiddleware())
//	router.Use(MetricsMiddleware())
//	router.Use(LoggerMiddleware(cfg))
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(RequestIDHeader)
		if id == "" {
			id = uuid.New().String()
		}

		// Store in context for use by handlers and other middleware (e.g. logging).
		c.Set(RequestIDKey, id)

		// Echo back to caller so they can correlate their request with server-side logs.
		c.Header(RequestIDHeader, id)

		c.Next()
	}
}
