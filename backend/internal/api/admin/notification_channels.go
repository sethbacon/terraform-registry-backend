// notification_channels.go implements admin CRUD + a test action for
// notification channels — additional delivery destinations (webhook, Slack,
// Microsoft Teams, or an ad-hoc email recipient list) for the
// module_published, approval_pending, cve_detected, and
// scanner_update_available events, alongside the shared SMTP recipients
// list. Target values are capability-bearing secrets, so they are encrypted
// at rest (via the shared token cipher) and never returned by the API.
package admin

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	identitycrypto "github.com/sethbacon/terraform-suite-identity/identity/crypto"
	identityhttpsafe "github.com/sethbacon/terraform-suite-identity/identity/httpsafe"

	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/notify"
)

var validNotificationChannelTypes = map[string]bool{"webhook": true, "slack": true, "teams": true, "email": true}

var validNotificationChannelEvents = map[string]bool{
	notify.EventModulePublished:        true,
	notify.EventApprovalPending:        true,
	notify.EventCVEDetected:            true,
	notify.EventScannerUpdateAvailable: true,
}

// NotificationChannelHandlers serves the notification-channel endpoints.
type NotificationChannelHandlers struct {
	repo        *repositories.NotificationChannelRepository
	notifier    *notify.Notifier
	tokenCipher *identitycrypto.TokenCipher
	// egress rejects a webhook/Slack/Teams target that resolves to a
	// denied range (loopback, link-local/metadata, RFC 1918, ...) at
	// create/update time, so an admin gets an immediate, clear error rather
	// than a silent dial-time failure. The Notifier's guarded client remains
	// the authoritative enforcement point at send time. nil = strict default.
	// Shares the same *identityhttpsafe.Guard instance passed to the Notifier
	// (router.go), so create-time validation and send-time enforcement apply
	// the identical security.egress.allowlist policy.
	egress *identityhttpsafe.Guard
}

// NewNotificationChannelHandlers builds the handlers over the app connection.
// guard applies the deployment egress policy (security.egress.allowlist) when
// validating a channel target URL on create/update.
func NewNotificationChannelHandlers(repo *repositories.NotificationChannelRepository, notifier *notify.Notifier, tokenCipher *identitycrypto.TokenCipher, guard *identityhttpsafe.Guard) *NotificationChannelHandlers {
	return &NotificationChannelHandlers{repo: repo, notifier: notifier, tokenCipher: tokenCipher, egress: guard}
}

type notificationChannelRequest struct {
	Name    string   `json:"name" binding:"required"`
	Type    string   `json:"type" binding:"required"`
	Target  string   `json:"target"` // destination URL or recipient list; write-only (omit on edit to keep existing)
	Events  []string `json:"events"`
	Enabled *bool    `json:"enabled"`
}

// validate checks the type, events, and (when present) the target. guard, when
// non-nil, additionally rejects a non-email (URL) target that violates the
// egress policy (private/metadata/loopback ranges) — defense in depth against
// SSRF via an admin-configured destination URL.
func (req *notificationChannelRequest) validate(guard *identityhttpsafe.Guard) error {
	if !validNotificationChannelTypes[req.Type] {
		return fmt.Errorf(`type must be one of "webhook", "slack", "teams", "email"`)
	}
	for _, e := range req.Events {
		if !validNotificationChannelEvents[e] {
			return fmt.Errorf("unknown event %q (allowed: module_published, approval_pending, cve_detected, scanner_update_available)", e)
		}
	}
	if req.Target != "" {
		if req.Type == "email" {
			// Email targets are recipient address(es), not a URL.
			if _, err := notify.ParseRecipients(req.Target); err != nil {
				return err
			}
		} else {
			u, err := url.Parse(req.Target)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("target must be a valid http(s) URL")
			}
			if guard != nil {
				if err := guard.ValidateURL(req.Target); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (req *notificationChannelRequest) events() []string {
	if req.Events == nil {
		return []string{}
	}
	return req.Events
}

// @Summary      List notification channels
// @Description  Returns all notification channels (destination secrets redacted). Requires admin scope.
// @Tags         Notifications
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Router       /api/v1/admin/notifications/channels [get]
func (h *NotificationChannelHandlers) ListChannels(c *gin.Context) {
	items, err := h.repo.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list channels"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"channels": items})
}

// @Summary      Create notification channel
// @Description  Registers a notification channel, encrypting its target. Requires admin scope.
// @Tags         Notifications
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  notificationChannelRequest  true  "Notification channel"
// @Success      201  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}  "Invalid input"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Router       /api/v1/admin/notifications/channels [post]
func (h *NotificationChannelHandlers) CreateChannel(c *gin.Context) {
	var req notificationChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and type are required"})
		return
	}
	if err := req.validate(h.egress); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target is required"})
		return
	}
	encrypted, err := h.tokenCipher.Seal(req.Target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt target"})
		return
	}
	enabled := req.Enabled == nil || *req.Enabled
	ch := &models.NotificationChannel{
		Name: req.Name, Type: req.Type, EncryptedTarget: encrypted, Events: req.events(), Enabled: enabled,
	}
	saved, err := h.repo.Create(c.Request.Context(), ch)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create channel"})
		return
	}
	c.JSON(http.StatusCreated, saved)
}

// @Summary      Update notification channel
// @Description  Replaces a channel. A blank target keeps the existing one. Requires admin scope.
// @Tags         Notifications
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path  string                       true  "Channel ID"
// @Param        body  body  notificationChannelRequest  true  "Notification channel"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}  "Invalid input"
// @Failure      404  {object}  map[string]interface{}  "Channel not found"
// @Router       /api/v1/admin/notifications/channels/{id} [put]
func (h *NotificationChannelHandlers) UpdateChannel(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel id"})
		return
	}
	var req notificationChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and type are required"})
		return
	}
	if err := req.validate(h.egress); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var encrypted string
	if req.Target != "" {
		var err error
		encrypted, err = h.tokenCipher.Seal(req.Target)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt target"})
			return
		}
	}
	enabled := req.Enabled == nil || *req.Enabled
	updated, err := h.repo.Update(c.Request.Context(), id, req.Name, req.Type, req.events(), enabled, encrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update channel"})
		return
	}
	if updated == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

// @Summary      Delete notification channel
// @Tags         Notifications
// @Security     Bearer
// @Success      204
// @Router       /api/v1/admin/notifications/channels/{id} [delete]
func (h *NotificationChannelHandlers) DeleteChannel(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel id"})
		return
	}
	if err := h.repo.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete channel"})
		return
	}
	c.Status(http.StatusNoContent)
}

// @Summary      Test notification channel
// @Description  Sends a fixed test message through a channel. Requires admin scope.
// @Tags         Notifications
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      404  {object}  map[string]interface{}  "Channel not found"
// @Failure      502  {object}  map[string]interface{}  "Delivery failed"
// @Router       /api/v1/admin/notifications/channels/{id}/test [post]
func (h *NotificationChannelHandlers) TestChannel(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel id"})
		return
	}
	if err := h.notifier.SendTest(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "sent"})
}
