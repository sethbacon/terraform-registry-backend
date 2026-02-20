// Package webhooks handles inbound webhook events from SCM providers (GitHub, GitLab, Azure DevOps,
// Bitbucket). When a tag is pushed to a repository linked to a module, the webhook triggers automatic
// module version publishing. Webhook payloads are validated against the provider's signature scheme
// before processing to prevent spoofed events.
package webhooks

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/scm"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// SCMWebhookHandler handles incoming SCM webhooks
type SCMWebhookHandler struct {
	scmRepo    *repositories.SCMRepository
	publisher  *services.SCMPublisher
	connectors map[scm.ProviderType]scm.Connector
}

// NewSCMWebhookHandler creates a new webhook handler
func NewSCMWebhookHandler(scmRepo *repositories.SCMRepository, publisher *services.SCMPublisher) *SCMWebhookHandler {
	return &SCMWebhookHandler{
		scmRepo:    scmRepo,
		publisher:  publisher,
		connectors: make(map[scm.ProviderType]scm.Connector),
	}
}

// @Summary      Receive SCM webhook
// @Description  Receives and processes incoming webhook events from SCM providers (GitHub, GitLab, Azure DevOps, Bitbucket).
// @Description  Two-layer security is applied: the URL-embedded secret (last path segment of the registered callback URL)
// @Description  is verified first with a constant-time comparison, and then the provider's HMAC payload signature is
// @Description  validated against the stored webhook secret. Both checks must pass before the payload is processed.
// @Description  Accepted events are logged. Tag-push events trigger asynchronous auto-publish when AutoPublish is enabled.
// @Tags         Webhooks
// @Accept       json
// @Produce      json
// @Param        module_source_repo_id  path  string  true  "Module source repository link ID (UUID) — uniquely identifies the SCM-to-module mapping"
// @Param        secret                 path  string  true  "URL-embedded webhook secret generated at link time; used as a first-line constant-time guard before HMAC validation"
// @Success      200  {object}  map[string]interface{}  "message: webhook received, log_id: UUID of the audit log entry"
// @Failure      400  {object}  map[string]interface{}  "Invalid repository ID or malformed/unreadable payload"
// @Failure      401  {object}  map[string]interface{}  "URL secret mismatch or HMAC payload signature invalid"
// @Failure      404  {object}  map[string]interface{}  "Repository link or SCM provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error (connector build, log write, etc.)"
// @Router       /webhooks/scm/{module_source_repo_id}/{secret} [post]
// HandleWebhook processes incoming webhooks from SCM providers
// POST /webhooks/scm/:module_source_repo_id/:secret
func (h *SCMWebhookHandler) HandleWebhook(c *gin.Context) {
	repoIDStr := c.Param("module_source_repo_id")
	requestSecret := c.Param("secret")

	repoID, err := uuid.Parse(repoIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repository ID"})
		return
	}

	// Read the webhook payload
	payloadBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read payload"})
		return
	}

	// Get the module source repository link
	moduleSourceRepo, err := h.scmRepo.GetModuleSourceRepo(c.Request.Context(), repoID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get repository link"})
		return
	}
	if moduleSourceRepo == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "repository link not found"})
		return
	}

	// Verify the URL-embedded secret to ensure the request came from the correct webhook endpoint.
	// The full webhook URL is stored in WebhookURL; its last path segment is the secret.
	if moduleSourceRepo.WebhookURL == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "webhook URL not configured"})
		return
	}
	storedSecret := path.Base(*moduleSourceRepo.WebhookURL)
	if subtle.ConstantTimeCompare([]byte(storedSecret), []byte(requestSecret)) != 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid webhook secret"})
		return
	}

	// Get the SCM provider
	provider, err := h.scmRepo.GetProvider(c.Request.Context(), moduleSourceRepo.SCMProviderID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get SCM provider"})
		return
	}
	if provider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SCM provider not found"})
		return
	}

	// Build connector for this provider
	baseURL := ""
	if provider.BaseURL != nil {
		baseURL = *provider.BaseURL
	}
	connector, err := scm.BuildConnector(&scm.ConnectorSettings{
		Kind:            provider.ProviderType,
		InstanceBaseURL: baseURL,
		ClientID:        provider.ClientID,
		ClientSecret:    provider.ClientSecretEncrypted, // Will need decryption
		CallbackURL:     "",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create connector"})
		return
	}

	// Extract headers
	headers := make(map[string]string)
	for key, values := range c.Request.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Verify webhook signature
	signatureHeader := h.getSignatureHeader(c.Request, provider.ProviderType)
	if !connector.VerifyDeliverySignature(payloadBytes, signatureHeader, provider.WebhookSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid webhook signature"})
		return
	}

	// Parse the webhook payload
	hook, err := connector.ParseDelivery(payloadBytes, headers)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse webhook"})
		return
	}

	// Log the webhook event
	logID := uuid.New()
	validSig := true
	webhookLog := &scm.SCMWebhookLogRecord{
		ID:              logID,
		ModuleSCMRepoID: repoID,
		EventID:         &hook.ID,
		EventType:       hook.Type,
		Ref:             &hook.Ref,
		CommitSHA:       &hook.CommitSHA,
		TagName:         &hook.TagName,
		Payload:         hook.Payload,
		Headers:         convertHeaders(headers),
		Signature:       &signatureHeader,
		SignatureValid:  &validSig,
		Processed:       false,
		CreatedAt:       time.Now(),
	}

	if err := h.scmRepo.CreateWebhookLog(c.Request.Context(), webhookLog); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to log webhook"})
		return
	}

	// Process the webhook asynchronously if it's a tag push
	if hook.IsTagEvent() && moduleSourceRepo.AutoPublish {
		go h.publisher.ProcessTagPush(c.Request.Context(), logID, moduleSourceRepo, hook, connector)
	}

	c.JSON(http.StatusOK, gin.H{"message": "webhook received", "log_id": logID})
}

func (h *SCMWebhookHandler) getSignatureHeader(req *http.Request, providerType scm.ProviderType) string {
	switch providerType {
	case scm.ProviderGitHub:
		return req.Header.Get("X-Hub-Signature-256")
	case scm.ProviderGitLab:
		return req.Header.Get("X-Gitlab-Token")
	case scm.ProviderAzureDevOps:
		return req.Header.Get("X-Vss-Signature")
	case scm.ProviderBitbucketDC:
		return req.Header.Get("X-Hub-Signature")
	default:
		return ""
	}
}

func formatHeaders(headers map[string]string) string {
	// Convert headers map to JSON string for storage
	result := ""
	for key, value := range headers {
		if result != "" {
			result += ", "
		}
		result += fmt.Sprintf("%s: %s", key, value)
	}
	return result
}

func convertHeaders(headers map[string]string) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range headers {
		result[key] = value
	}
	return result
}
