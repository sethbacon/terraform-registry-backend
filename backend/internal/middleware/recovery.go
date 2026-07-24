package middleware

import (
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

// sensitiveRecoveryHeaders lists the request headers a panic-recovery dump
// must redact before logging. gin's stock Recovery() only sanitizes
// Authorization -- its own recovery.go documents this precisely:
// "Currently, only the Authorization header is sanitized. All other headers
// and request data remain unchanged." This service authenticates JWT
// sessions via cookie as well as Bearer (see internal/auth/jwt.go), so an
// unredacted Cookie header written to the panic log is a live session token
// (issue #663).
var sensitiveRecoveryHeaders = map[string]bool{
	"Authorization": true,
	"Cookie":        true,
	"Set-Cookie":    true,
}

// redactedRequestDump returns a request-line-and-headers dump (no body, so
// request bodies are never logged) with every sensitiveRecoveryHeaders value
// masked, and the request line's path/query routed through the same
// RedactSensitivePath/RedactSensitiveQuery helpers LoggerMiddleware and
// AuditMiddleware use (#678 sibling). httputil.DumpRequest's first line is
// the request line ("METHOD /path?query HTTP/1.1") reconstructed from r.URL,
// so without this a webhook secret path segment or an OAuth code/state/token
// query parameter would be written to the panic log verbatim.
func redactedRequestDump(r *http.Request) string {
	dump, err := httputil.DumpRequest(r, false)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(dump), "\r\n")
	if len(lines) > 0 {
		lines[0] = redactedRequestLine(lines[0])
	}
	for i, line := range lines {
		if idx := strings.Index(line, ":"); idx > 0 {
			name := http.CanonicalHeaderKey(strings.TrimSpace(line[:idx]))
			if sensitiveRecoveryHeaders[name] {
				lines[i] = line[:idx] + ": [REDACTED]"
			}
		}
	}
	return strings.Join(lines, "\r\n")
}

// redactedRequestLine rewrites a dumped "METHOD /path?query HTTP/x.y"
// request line, redacting the path and query via RedactSensitivePath and
// RedactSensitiveQuery. Lines that don't match the expected three-field
// request-line shape are returned unchanged.
func redactedRequestLine(line string) string {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return line
	}
	method, uri, proto := parts[0], parts[1], parts[2]
	path, query, _ := strings.Cut(uri, "?")
	path = RedactSensitivePath(path)
	query = RedactSensitiveQuery(query)
	if query != "" {
		return method + " " + path + "?" + query + " " + proto
	}
	return method + " " + path + " " + proto
}

// RecoveryMiddleware recovers from panics during request handling and
// responds 500, logging the panic value, stack trace, and a redacted request
// dump. It replaces gin.Recovery(), whose built-in request dump leaves the
// Cookie/Set-Cookie header -- a live session/JWT token for this app --
// completely unredacted on every panic (issue #663).
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}

			// A broken client connection is not a real error condition; gin's
			// own Recovery() treats it the same way, logging without a stack
			// trace and letting the connection close instead of writing a
			// status to it.
			var isBrokenPipe bool
			if err, ok := rec.(error); ok {
				isBrokenPipe = errors.Is(err, syscall.EPIPE) ||
					errors.Is(err, syscall.ECONNRESET) ||
					errors.Is(err, http.ErrAbortHandler)
			}

			if isBrokenPipe {
				log.Printf("%s\n%s", rec, redactedRequestDump(c.Request))
				c.Error(rec.(error)) //nolint:errcheck
				c.Abort()
				return
			}

			log.Printf("[Recovery] %s panic recovered:\n%s\n%s\n%s",
				time.Now().Format("2006/01/02 - 15:04:05"), redactedRequestDump(c.Request), rec, debug.Stack())
			c.AbortWithStatus(http.StatusInternalServerError)
		}()
		c.Next()
	}
}
