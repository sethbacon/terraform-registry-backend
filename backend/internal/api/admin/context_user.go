// context_user.go holds the single spelling of "who is making this request",
// read from the gin context the auth middleware populates.
//
// WHY THIS FILE EXISTS (issue #899)
//
// middleware.AuthMiddleware stores the principal as `c.Set("user_id", user.ID)`
// and models.User.ID is a STRING. Four attribution sites asserted
// `userID.(uuid.UUID)` instead, so the assertion never succeeded, the value was
// silently dropped, and the column was written NULL on every request:
//
//	admin/storage.go           -> storage_config.created_by / .updated_by
//	admin/storage_migration.go -> storage_migrations.created_by
//	admin/mirror.go            -> mirror_configurations.created_by
//
// Nothing failed and nothing logged; the columns simply never held a value.
// That is also why migration 000056 (issue #883) could drop the foreign keys on
// three of them as "on a column that is always NULL" -- the constraints looked
// harmless because the bug upstream of them made them unreachable.
//
// Both concrete types are accepted rather than only the string the middleware
// writes. Tests set a uuid.UUID directly (TestMirrorCreate_WithUserIDContext),
// and accepting one spelling while the codebase contains both is exactly how
// the original defect survived: the failure mode of a type assertion here is a
// missing value, never an error.
package admin

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// currentUserID extracts the authenticated user's UUID from the gin context,
// or nil when absent/unparsable (e.g. API-key auth without a user binding).
func currentUserID(c *gin.Context) *uuid.UUID {
	v, ok := c.Get("user_id")
	if !ok {
		return nil
	}
	switch id := v.(type) {
	case string:
		parsed, err := uuid.Parse(id)
		if err != nil {
			return nil
		}
		return &parsed
	case uuid.UUID:
		if id == uuid.Nil {
			return nil
		}
		return &id
	}
	return nil
}

// currentUserNullUUID is currentUserID in the shape the storage-config columns
// take: a uuid.NullUUID that is Valid only when a principal was resolved, so an
// unattributable request still writes SQL NULL rather than the zero UUID.
func currentUserNullUUID(c *gin.Context) uuid.NullUUID {
	if id := currentUserID(c); id != nil {
		return uuid.NullUUID{UUID: *id, Valid: true}
	}
	return uuid.NullUUID{}
}

// currentUserIDString is currentUserID for the call sites that pass the
// principal on as a string. Empty means "no principal", which every consumer
// already renders as NULL.
func currentUserIDString(c *gin.Context) string {
	if id := currentUserID(c); id != nil {
		return id.String()
	}
	return ""
}
