// admin_floor.go maps internal/adminfloor's refusals onto HTTP answers for
// every handler in this package that reduces administrative authority
// (issue #766).
//
// One mapper rather than a switch per handler: the two invariants are refused
// for the same reason wherever they are refused, and a caller that has to
// discover a different status or a different error key on each route cannot
// write one retry rule. It also means a new call site gets the right answer by
// construction, which is the property admin_floor_class_test.go asserts.
package admin

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
)

// Error strings, exported as constants so tests assert the exact text rather
// than "not 200" — and so the frontend has something stable to match.
const (
	// ErrMsgLastPlatformAdmin is the refusal for invariant A.
	ErrMsgLastPlatformAdmin = "This would leave the deployment with no platform administrator"
	// ErrMsgLastOrganizationAdmin is the refusal for invariant B.
	ErrMsgLastOrganizationAdmin = "This would leave the organization with no administrator"
	// ErrMsgFloorIndeterminate is the answer when the floor could not be
	// established. Deliberately NOT a refusal message: nothing was decided.
	ErrMsgFloorIndeterminate = "Failed to verify that an administrator would remain"
)

// respondAdminFloor writes the HTTP answer for an adminfloor error and reports
// whether it handled one. A caller that gets false must handle err itself.
//
// 409 for both refusals, matching RevokePlatformAdmin's existing answer for
// the same class of conflict (PR #862): the request is well-formed and the
// caller is authorized — it is the state of the world that forbids it, and
// the caller can make it succeed by granting somebody else the authority
// first.
//
// 500 for an unresolved floor. An unresolved answer is not permission and is
// not a policy refusal; reporting it as 409 would tell an operator to go and
// appoint a second administrator they may already have.
func respondAdminFloor(c *gin.Context, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, adminfloor.ErrLastPlatformAdmin):
		c.JSON(http.StatusConflict, gin.H{
			"error":   ErrMsgLastPlatformAdmin,
			"details": "Grant platform-admin to another user first. A deployment with no platform administrator cannot be recovered through this API.",
		})
		return true
	case errors.Is(err, adminfloor.ErrLastOrganizationAdmin):
		c.JSON(http.StatusConflict, gin.H{
			"error":   ErrMsgLastOrganizationAdmin,
			"details": "Give another member of this organization a role carrying organizations:write first, or remove its remaining members as well.",
		})
		return true
	case errors.Is(err, adminfloor.ErrIndeterminate):
		slog.Error("administrator floor could not be established; the change was refused", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrMsgFloorIndeterminate})
		return true
	}
	return false
}
