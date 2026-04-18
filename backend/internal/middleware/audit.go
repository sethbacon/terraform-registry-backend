// audit.go provides Gin middleware that records authenticated write operations to the audit
// log, with optional shipping to external audit destinations.
package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// AuditMiddleware logs authenticated actions to the database only (backward compatible)
func AuditMiddleware(auditRepo *repositories.AuditRepository) gin.HandlerFunc {
	return AuditMiddlewareWithShipper(auditRepo, nil, nil)
}

// AuditMiddlewareWithShipper logs authenticated actions and ships to external destinations
func AuditMiddlewareWithShipper(auditRepo *repositories.AuditRepository, shipper audit.Shipper, auditCfg *config.AuditConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Process request first
		c.Next()

		// Skip OPTIONS always
		if c.Request.Method == "OPTIONS" {
			return
		}

		// Determine what to log based on config
		logReadOps := auditCfg != nil && auditCfg.LogReadOperations
		logFailedReqs := auditCfg != nil && auditCfg.LogFailedRequests

		isReadOp := c.Request.Method == "GET"
		isFailed := c.Writer.Status() >= 400

		// Default behavior: only log successful write operations
		if auditCfg == nil {
			if isReadOp || isFailed {
				return
			}
		} else {
			// With config: check specific settings
			if isReadOp && !logReadOps {
				return
			}
			if isFailed && !logFailedReqs {
				// Skip failed operations if not configured to log them
				return
			}
		}

		// Extract context
		userID, _ := c.Get("user_id")
		orgID, _ := c.Get("organization_id")
		authMethod, _ := c.Get("auth_method")

		// Create audit log entry
		action := fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path)
		ipAddress := c.ClientIP()

		auditLog := &models.AuditLog{
			Action:    action,
			IPAddress: &ipAddress,
			CreatedAt: time.Now(),
		}

		// Set user ID if present
		var userIDStr string
		if userID != nil {
			if uid, ok := userID.(string); ok {
				userIDStr = uid
				auditLog.UserID = &userIDStr
			}
		}

		// Set organization ID if present
		var orgIDStr string
		if orgID != nil {
			if oid, ok := orgID.(string); ok {
				orgIDStr = oid
				auditLog.OrganizationID = &orgIDStr
			}
		}

		// Set resource type based on URL path
		resourceType := getResourceType(c)
		auditLog.ResourceType = &resourceType

		// Add specific mirror action details
		if resourceType == "mirror" {
			if strings.Contains(c.Request.URL.Path, "/sync") {
				action = "mirror.sync_triggered"
			} else if c.Request.Method == "POST" {
				action = "mirror.created"
			} else if c.Request.Method == "PUT" {
				action = "mirror.updated"
			} else if c.Request.Method == "DELETE" {
				action = "mirror.deleted"
			}
			auditLog.Action = action
		}

		// Extract metadata from context if available
		metadata := make(map[string]interface{})

		if authMethod != nil {
			metadata["auth_method"] = authMethod
		}
		metadata["status_code"] = c.Writer.Status()

		if len(metadata) > 0 {
			auditLog.Metadata = metadata
		}

		// Async log creation (non-blocking)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Write to database
			if auditRepo != nil {
				if err := auditRepo.CreateAuditLog(ctx, auditLog); err != nil {
					slog.Error("failed to create audit log", "error", err)
				}
			}

			// Ship to external destinations
			if shipper != nil {
				authMethodStr := ""
				if am, ok := authMethod.(string); ok {
					authMethodStr = am
				}

				entry := &audit.LogEntry{
					Timestamp:      auditLog.CreatedAt,
					Action:         auditLog.Action,
					UserID:         userIDStr,
					OrganizationID: orgIDStr,
					ResourceType:   resourceType,
					IPAddress:      ipAddress,
					AuthMethod:     authMethodStr,
					StatusCode:     c.Writer.Status(),
					Metadata:       metadata,
				}

				if err := shipper.Ship(ctx, entry); err != nil {
					slog.Error("failed to ship audit log", "error", err)
				}
			}
		}()
	}
}

func getResourceType(c *gin.Context) string {
	fullPath := c.FullPath()
	switch {
	case strings.HasPrefix(fullPath, "/api/v1/modules"):
		return "module"
	case strings.HasPrefix(fullPath, "/api/v1/providers"):
		return "provider"
	case strings.HasPrefix(fullPath, "/api/v1/admin/mirrors"):
		return "mirror"
	case strings.HasPrefix(fullPath, "/api/v1/admin/users"):
		return "user"
	case strings.HasPrefix(fullPath, "/api/v1/admin/apikeys"):
		return "api_key"
	case strings.HasPrefix(fullPath, "/api/v1/admin/organizations"):
		return "organization"
	case strings.HasPrefix(fullPath, "/api/v1/admin/storage"):
		return "storage"
	case strings.HasPrefix(fullPath, "/api/v1/admin/roles"):
		return "role"
	case strings.HasPrefix(fullPath, "/api/v1/admin/scm-providers"):
		return "scm_provider"
	case strings.HasPrefix(fullPath, "/api/v1/admin/webhooks"):
		return "webhook"
	case strings.HasPrefix(fullPath, "/api/v1/admin/scanning"),
		strings.HasPrefix(fullPath, "/api/v1/admin/security-scanning"):
		return "scanning"
	case strings.HasPrefix(fullPath, "/api/v1/admin/approvals"):
		return "approval"
	case strings.HasPrefix(fullPath, "/api/v1/admin/terraform-mirror"):
		return "terraform_mirror"
	case strings.HasPrefix(fullPath, "/api/v1/admin/binary-mirror"):
		return "binary_mirror"
	case strings.HasPrefix(fullPath, "/api/v1/admin/policies"):
		return "policy"
	case strings.HasPrefix(fullPath, "/api/v1/admin/setup"),
		strings.HasPrefix(fullPath, "/api/v1/setup"):
		return "setup"
	case strings.HasPrefix(fullPath, "/api/v1/auth"):
		return "auth"
	default:
		return "unknown"
	}
}
