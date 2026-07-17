// notifications.go implements admin endpoints for viewing and updating the
// outbound notification (SMTP) configuration shared by the CVE poll job, the
// API key expiry notifier, and the scanner update job, plus a send-test-email
// probe. The SMTP password is write-only: it is encrypted at rest (via the
// shared token cipher) and never returned by the API.
package admin

import (
	"encoding/json"
	"net/http"
	"net/mail"

	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/notify"
)

// NotificationsConfigDB is the persistence shape stored in
// system_settings.notifications_config. It is exported so router.go can reuse
// it when reloading the persisted configuration into cfg.Notifications at
// startup.
type NotificationsConfigDB struct {
	Enabled                        bool     `json:"enabled"`
	APIKeyExpiryWarningDays        int      `json:"api_key_expiry_warning_days,omitempty"`
	APIKeyExpiryCheckIntervalHours int      `json:"api_key_expiry_check_interval_hours,omitempty"`
	Recipients                     []string `json:"recipients,omitempty"`
	// Events is a pointer so a persisted config saved before this feature
	// existed (nil) can be distinguished from one that explicitly disabled
	// every event type — resolveEvents treats nil as "all events enabled".
	Events *NotificationEventsJSON `json:"events,omitempty"`
	SMTP   struct {
		Host              string `json:"host"`
		Port              int    `json:"port"`
		Username          string `json:"username"`
		From              string `json:"from"`
		UseTLS            bool   `json:"use_tls"`
		PasswordEncrypted string `json:"smtp_password_encrypted,omitempty"`
	} `json:"smtp"`
}

// NotificationEventsJSON is the wire/persistence shape of
// config.NotificationEventsConfig (snake_case field names matching the
// frontend and the YAML/env "notifications.events.*" keys). Field names,
// types, and order match config.NotificationEventsConfig exactly, so the two
// are directly convertible (config.NotificationEventsConfig(x) /
// NotificationEventsJSON(y)) without a field-by-field copy.
type NotificationEventsJSON struct {
	APIKeyExpiring         bool `json:"api_key_expiring"`
	ModulePublished        bool `json:"module_published"`
	ApprovalPending        bool `json:"approval_pending"`
	CVEDetected            bool `json:"cve_detected"`
	ScannerUpdateAvailable bool `json:"scanner_update_available"`
}

// NotificationsConfigResponse is the redacted public view of the notifications
// config. The SMTP password/ciphertext is never included.
type NotificationsConfigResponse struct {
	Enabled                        bool                      `json:"enabled"`
	SMTP                           NotificationsSMTPResponse `json:"smtp"`
	Recipients                     []string                  `json:"recipients"`
	Events                         NotificationEventsJSON    `json:"events"`
	APIKeyExpiryWarningDays        int                       `json:"api_key_expiry_warning_days"`
	APIKeyExpiryCheckIntervalHours int                       `json:"api_key_expiry_check_interval_hours"`
	PasswordConfigured             bool                      `json:"password_configured"`
}

// NotificationsSMTPResponse is the redacted SMTP portion of NotificationsConfigResponse.
type NotificationsSMTPResponse struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	From     string `json:"from"`
	UseTLS   bool   `json:"use_tls"`
}

// notificationsConfigInput is the PUT request body.
type notificationsConfigInput struct {
	Enabled bool `json:"enabled"`
	SMTP    struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		From     string `json:"from"`
		UseTLS   bool   `json:"use_tls"`
	} `json:"smtp"`
	Recipients                     []string               `json:"recipients"`
	Events                         NotificationEventsJSON `json:"events"`
	APIKeyExpiryWarningDays        int                    `json:"api_key_expiry_warning_days"`
	APIKeyExpiryCheckIntervalHours int                    `json:"api_key_expiry_check_interval_hours"`
}

// notificationsTestEmailInput is the POST /admin/notifications/test request body.
// All fields are optional: recipients default to cve.email_recipients, and any
// omitted smtp override field falls back to the live notifications config.
type notificationsTestEmailInput struct {
	Recipients []string `json:"recipients"`
	Subject    string   `json:"subject"`
	SMTP       *struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		From     string `json:"from"`
		UseTLS   *bool  `json:"use_tls"`
	} `json:"smtp"`
}

// NotificationsHandler handles the admin notifications-config endpoints.
type NotificationsHandler struct {
	cfg         *config.NotificationsConfig
	repo        *repositories.OIDCConfigRepository
	tokenCipher *crypto.TokenCipher
	cveCfg      *config.CVEConfig
}

// NewNotificationsHandler constructs a NotificationsHandler. cfg must be a
// pointer to the live config.Notifications struct so updates take effect
// in-place for background jobs holding the same pointer.
func NewNotificationsHandler(
	cfg *config.NotificationsConfig,
	repo *repositories.OIDCConfigRepository,
	tokenCipher *crypto.TokenCipher,
	cveCfg *config.CVEConfig,
) *NotificationsHandler {
	return &NotificationsHandler{
		cfg:         cfg,
		repo:        repo,
		tokenCipher: tokenCipher,
		cveCfg:      cveCfg,
	}
}

// toResponse builds the redacted response shape shared by GetConfig and PutConfig.
func (h *NotificationsHandler) toResponse(passwordConfigured bool) NotificationsConfigResponse {
	// A nil slice marshals to JSON `null`, not `[]` -- the frontend calls
	// .join() on this field unconditionally, so a null response throws
	// "Cannot read properties of null (reading 'join')" and crashes the
	// admin Notifications page. Normalize to an empty slice so the field is
	// always a real (possibly empty) JSON array.
	recipients := h.cfg.Recipients
	if recipients == nil {
		recipients = []string{}
	}
	return NotificationsConfigResponse{
		Enabled: h.cfg.Enabled,
		SMTP: NotificationsSMTPResponse{
			Host:     h.cfg.SMTP.Host,
			Port:     h.cfg.SMTP.Port,
			Username: h.cfg.SMTP.Username,
			From:     h.cfg.SMTP.From,
			UseTLS:   h.cfg.SMTP.UseTLS,
		},
		Recipients:                     recipients,
		Events:                         NotificationEventsJSON(h.cfg.Events),
		APIKeyExpiryWarningDays:        h.cfg.APIKeyExpiryWarningDays,
		APIKeyExpiryCheckIntervalHours: h.cfg.APIKeyExpiryCheckIntervalHours,
		PasswordConfigured:             passwordConfigured,
	}
}

// @Summary      Get notifications configuration
// @Description  Returns the current outbound-notification (SMTP) configuration. The SMTP password is never returned; password_configured indicates whether one is set. Requires admin scope.
// @Tags         Notifications
// @Security     Bearer
// @Produce      json
// @Success      200  {object}  NotificationsConfigResponse
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Router       /api/v1/admin/notifications/config [get]
// GetConfig returns the current notifications configuration (password redacted).
func (h *NotificationsHandler) GetConfig(c *gin.Context) {
	ctx := c.Request.Context()

	passwordConfigured := h.cfg.SMTP.Password != ""
	if raw, err := h.repo.GetNotificationsConfig(ctx); err == nil && raw != nil {
		var dbc NotificationsConfigDB
		if json.Unmarshal(raw, &dbc) == nil && dbc.SMTP.PasswordEncrypted != "" {
			passwordConfigured = true
		}
	}

	c.JSON(http.StatusOK, h.toResponse(passwordConfigured))
}

// @Summary      Update notifications configuration
// @Description  Updates the outbound-notification (SMTP) configuration. The SMTP password is write-only: send a non-empty value to change it, or omit/blank it to preserve the currently stored password. Requires admin scope.
// @Tags         Notifications
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  notificationsConfigInput  true  "Notifications configuration"
// @Success      200  {object}  NotificationsConfigResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid configuration input"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/admin/notifications/config [put]
// PutConfig validates and persists the notifications configuration, then updates
// the in-memory config in place so background jobs observe the change immediately.
func (h *NotificationsHandler) PutConfig(c *gin.Context) {
	ctx := c.Request.Context()

	var input notificationsConfigInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.SMTP.Port == 0 {
		input.SMTP.Port = 587
	}
	if err := validateNotificationsInput(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var existingEncrypted string
	if raw, err := h.repo.GetNotificationsConfig(ctx); err == nil && raw != nil {
		var existing NotificationsConfigDB
		if json.Unmarshal(raw, &existing) == nil {
			existingEncrypted = existing.SMTP.PasswordEncrypted
		}
	}

	dbc, err := buildNotificationsConfigDB(input, h.tokenCipher, existingEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt smtp password"})
		return
	}

	configJSON, err := json.Marshal(dbc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal notifications configuration"})
		return
	}
	if err := h.repo.SetNotificationsConfig(ctx, configJSON); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save notifications configuration"})
		return
	}

	// Update the in-memory config in place (never reassign h.cfg) so the CVE
	// poll job, API key expiry notifier, and scanner update job all observe
	// the new settings on their next run.
	h.cfg.Enabled = input.Enabled
	h.cfg.SMTP.Host = input.SMTP.Host
	h.cfg.SMTP.Port = input.SMTP.Port
	h.cfg.SMTP.Username = input.SMTP.Username
	h.cfg.SMTP.From = input.SMTP.From
	h.cfg.SMTP.UseTLS = input.SMTP.UseTLS
	h.cfg.Recipients = input.Recipients
	h.cfg.Events = config.NotificationEventsConfig(input.Events)
	h.cfg.APIKeyExpiryWarningDays = input.APIKeyExpiryWarningDays
	h.cfg.APIKeyExpiryCheckIntervalHours = input.APIKeyExpiryCheckIntervalHours
	if input.SMTP.Password != "" {
		h.cfg.SMTP.Password = input.SMTP.Password
	}

	passwordConfigured := dbc.SMTP.PasswordEncrypted != "" || h.cfg.SMTP.Password != ""
	c.JSON(http.StatusOK, h.toResponse(passwordConfigured))
}

// validateNotificationsInput checks the basic field constraints for a PUT
// request: when enabled, host and from are required; the port (after the
// caller applies the 0->587 default) must be a valid TCP port; and from, when
// present, must be a syntactically valid email address.
func validateNotificationsInput(input *notificationsConfigInput) error {
	if input.SMTP.Port < 1 || input.SMTP.Port > 65535 {
		return &ValidationError{Field: "smtp.port", Message: "must be between 1 and 65535"}
	}
	if input.Enabled {
		if input.SMTP.Host == "" {
			return &ValidationError{Field: "smtp.host", Message: "required when notifications are enabled"}
		}
		if input.SMTP.From == "" {
			return &ValidationError{Field: "smtp.from", Message: "required when notifications are enabled"}
		}
	}
	if input.SMTP.From != "" {
		if _, err := mail.ParseAddress(input.SMTP.From); err != nil {
			return &ValidationError{Field: "smtp.from", Message: "must be a valid email address"}
		}
	}
	return nil
}

// buildNotificationsConfigDB maps a validated PUT input to the DB persistence
// shape, applying the seal/empty-password rule: a non-empty input password is
// sealed into SMTP.PasswordEncrypted; an empty password preserves
// existingEncrypted (the previously persisted ciphertext, if any).
func buildNotificationsConfigDB(input notificationsConfigInput, tokenCipher *crypto.TokenCipher, existingEncrypted string) (NotificationsConfigDB, error) {
	var dbc NotificationsConfigDB
	dbc.Enabled = input.Enabled
	dbc.APIKeyExpiryWarningDays = input.APIKeyExpiryWarningDays
	dbc.APIKeyExpiryCheckIntervalHours = input.APIKeyExpiryCheckIntervalHours
	dbc.Recipients = input.Recipients
	events := input.Events
	dbc.Events = &events
	dbc.SMTP.Host = input.SMTP.Host
	dbc.SMTP.Port = input.SMTP.Port
	dbc.SMTP.Username = input.SMTP.Username
	dbc.SMTP.From = input.SMTP.From
	dbc.SMTP.UseTLS = input.SMTP.UseTLS

	if input.SMTP.Password != "" {
		encrypted, err := tokenCipher.Seal(input.SMTP.Password)
		if err != nil {
			return dbc, err
		}
		dbc.SMTP.PasswordEncrypted = encrypted
	} else {
		dbc.SMTP.PasswordEncrypted = existingEncrypted
	}
	return dbc, nil
}

// @Summary      Send a test notification email
// @Description  Sends a test email using the current (or request-overridden) SMTP configuration, without saving anything. Recipients default to cve.email_recipients when omitted. Always returns 200 with {success,message}, even when the send fails. Requires admin scope.
// @Tags         Notifications
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        body  body  notificationsTestEmailInput  true  "Test email parameters"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}  "Missing recipients or SMTP host"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Router       /api/v1/admin/notifications/test [post]
// TestEmail sends a test notification email without persisting any configuration.
// coverage:skip:integration-only — the success/failure result comes from a live mailer.Send (SMTP dial); the validation branches (missing recipients, missing host) are covered by TestNotificationsHandler_TestEmail_* without ever reaching Send.
func (h *NotificationsHandler) TestEmail(c *gin.Context) {
	ctx := c.Request.Context()

	var input notificationsTestEmailInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tempSMTP := h.cfg.SMTP
	if input.SMTP != nil {
		if input.SMTP.Host != "" {
			tempSMTP.Host = input.SMTP.Host
		}
		if input.SMTP.Port != 0 {
			tempSMTP.Port = input.SMTP.Port
		}
		if input.SMTP.Username != "" {
			tempSMTP.Username = input.SMTP.Username
		}
		if input.SMTP.From != "" {
			tempSMTP.From = input.SMTP.From
		}
		if input.SMTP.UseTLS != nil {
			tempSMTP.UseTLS = *input.SMTP.UseTLS
		}
		if input.SMTP.Password != "" {
			tempSMTP.Password = input.SMTP.Password
		}
	}

	// When the request omits the password, fall back to the decrypted stored
	// password rather than whatever happens to be in the in-memory config
	// (which may be empty if the process hasn't reloaded since a PUT).
	if input.SMTP == nil || input.SMTP.Password == "" {
		if raw, err := h.repo.GetNotificationsConfig(ctx); err == nil && raw != nil {
			var dbc NotificationsConfigDB
			if json.Unmarshal(raw, &dbc) == nil && dbc.SMTP.PasswordEncrypted != "" {
				if pw, derr := h.tokenCipher.Open(dbc.SMTP.PasswordEncrypted); derr == nil {
					tempSMTP.Password = pw
				}
			}
		}
	}

	recipients := input.Recipients
	if len(recipients) == 0 {
		recipients = h.cveCfg.EmailRecipients
	}
	if len(recipients) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one recipient is required"})
		return
	}
	if tempSMTP.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "smtp host is not configured"})
		return
	}

	subject := input.Subject
	if subject == "" {
		subject = "Terraform Registry: test notification"
	}
	body := "This is a test notification email sent from the Terraform Registry admin notifications settings."

	mailer := notify.New(&tempSMTP)
	if err := mailer.Send(recipients, subject, body); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "failed to send test email: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "test email sent"})
}
