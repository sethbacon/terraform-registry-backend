package api

import "strings"

// redactSensitivePath masks secret URL segments before logging.
//
//	/webhooks/scm/<id>/<secret>  -> /webhooks/scm/<id>/[REDACTED]
//	/webhooks/approvals/<token>  -> /webhooks/approvals/[REDACTED]
func redactSensitivePath(p string) string {
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
