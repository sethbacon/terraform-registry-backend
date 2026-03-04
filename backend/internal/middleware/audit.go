// audit.go provides Gin middleware that records authenticated write operations to the audit
// log, with optional shipping to external audit destinations.
package middleware

import (
	"context"
	"fmt"
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
			if isFailed && !logFailedReqs && isReadOp {
				// Skip failed read operations if not configured to log them
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
		var resourceType string
		if contains(c.Request.URL.Path, "/modules") {
			resourceType = "module"
			auditLog.ResourceType = &resourceType
		} else if contains(c.Request.URL.Path, "/mirrors") {
			resourceType = "mirror"
			auditLog.ResourceType = &resourceType
			// Add specific mirror action details
			if contains(c.Request.URL.Path, "/sync") {
				action = "mirror.sync_triggered"
			} else if c.Request.Method == "POST" {
				action = "mirror.created"
			} else if c.Request.Method == "PUT" {
				action = "mirror.updated"
			} else if c.Request.Method == "DELETE" {
				action = "mirror.deleted"
			}
			auditLog.Action = action
		} else if contains(c.Request.URL.Path, "/providers") {
			resourceType = "provider"
			auditLog.ResourceType = &resourceType
		} else if contains(c.Request.URL.Path, "/users") {
			resourceType = "user"
			auditLog.ResourceType = &resourceType
		} else if contains(c.Request.URL.Path, "/apikeys") {
			resourceType = "api_key"
			auditLog.ResourceType = &resourceType
		} else if contains(c.Request.URL.Path, "/organizations") {
			resourceType = "organization"
			auditLog.ResourceType = &resourceType
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
					fmt.Printf("Failed to create audit log in database: %v\n", err)
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
					fmt.Printf("Failed to ship audit log: %v\n", err)
				}
			}
		}()
	}
}

// contains is a simple helper to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			indexOf(s, substr) >= 0))
}

// indexOf returns the index of the first instance of substr in s, or -1 if substr is not present
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
