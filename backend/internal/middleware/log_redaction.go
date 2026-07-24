package middleware

import (
	"net/url"
	"strings"
)

// sensitiveQueryParams lists query-string keys that must never be logged verbatim.
// OAuth/OIDC authorization codes and CSRF state values are single-use-but-replayable
// bearer credentials during their validity window (e.g. GET /api/v1/auth/callback
// and GET /api/v1/scm-providers/:id/oauth/callback both put these in the query
// string), and log aggregation/SIEM pipelines may have broader read access than
// the application itself.
var sensitiveQueryParams = map[string]bool{
	"code":          true,
	"state":         true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"id_token":      true,
	"client_secret": true,
	"api_key":       true,
	"secret":        true,
}

// RedactSensitiveQuery masks known-sensitive query parameter values before logging.
// Malformed query strings are redacted wholesale rather than risk leaking them verbatim.
//
// Exported so both api.LoggerMiddleware and AuditMiddleware share this one
// implementation instead of each keeping their own copy (issue #678).
func RedactSensitiveQuery(rawQuery string) string {
	if rawQuery == "" {
		return rawQuery
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "[REDACTED]"
	}
	redacted := false
	for key := range values {
		if sensitiveQueryParams[strings.ToLower(key)] {
			values.Set(key, "[REDACTED]")
			redacted = true
		}
	}
	if !redacted {
		return rawQuery
	}
	return values.Encode()
}

// RedactSensitivePath masks secret URL segments before logging.
//
//	/webhooks/scm/<id>/<secret>  -> /webhooks/scm/<id>/[REDACTED]
//	/webhooks/approvals/<token>  -> /webhooks/approvals/[REDACTED]
//
// Exported so both api.LoggerMiddleware and AuditMiddleware share this one
// implementation instead of each keeping their own copy (issue #678).
func RedactSensitivePath(p string) string {
	switch {
	case strings.HasPrefix(p, "/webhooks/scm/"):
		parts := strings.Split(p, "/")
		if len(parts) >= 5 {
			parts[4] = "[REDACTED]"
			return strings.Join(parts[:5], "/")
		}
		if len(parts) == 4 {
			parts[3] = "[REDACTED]"
			return strings.Join(parts[:4], "/")
		}
	case strings.HasPrefix(p, "/webhooks/approvals/"):
		parts := strings.Split(p, "/")
		if len(parts) >= 4 {
			parts[3] = "[REDACTED]"
			return strings.Join(parts[:4], "/")
		}
	}
	return p
}
