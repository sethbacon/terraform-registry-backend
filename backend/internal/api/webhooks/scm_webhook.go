// Package webhooks handles inbound webhook events from SCM providers (GitHub, GitLab, Azure DevOps,
// Bitbucket). When a tag is pushed to a repository linked to a module, the webhook triggers automatic
// module version publishing. Webhook payloads are validated against the provider's signature scheme
// before processing to prevent spoofed events.
package webhooks

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/safego"
	"github.com/terraform-registry/terraform-registry/internal/scm"
	"github.com/terraform-registry/terraform-registry/internal/services"
)

// SCMWebhookHandler handles incoming SCM webhooks
type SCMWebhookHandler struct {
	scmRepo     *repositories.SCMRepository
	publisher   *services.SCMPublisher
	connectors  map[scm.ProviderType]scm.Connector
	tokenCipher *crypto.TokenCipher
}

// NewSCMWebhookHandler creates a new webhook handler
func NewSCMWebhookHandler(scmRepo *repositories.SCMRepository, publisher *services.SCMPublisher, tokenCipher *crypto.TokenCipher) *SCMWebhookHandler {
	return &SCMWebhookHandler{
		scmRepo:     scmRepo,
		publisher:   publisher,
		connectors:  make(map[scm.ProviderType]scm.Connector),
		tokenCipher: tokenCipher,
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
// @Success      200  {object}  webhooks.WebhookReceivedResponse
// @Failure      400  {object}  map[string]interface{}  "Invalid repository ID or malformed/unreadable payload"
// @Failure      401  {object}  map[string]interface{}  "URL secret mismatch or HMAC payload signature invalid"
// @Failure      404  {object}  map[string]interface{}  "Repository link or SCM provider not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error (connector build, log write, etc.)"
// @Router       /webhooks/scm/{module_source_repo_id}/{secret} [post]
// maxWebhookPayloadBytes caps the unauthenticated webhook body.
//
// 5 MiB is comfortably above every real SCM push payload -- GitHub documents a
// 25 MB delivery ceiling but real push/PR events are kilobytes, and this handler
// only reads a handful of fields -- while being small enough that concurrent
// abuse cannot exhaust the process. Sized from what the sender actually sends
// rather than from what the protocol permits.
const maxWebhookPayloadBytes = 5 << 20

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

	// Read the webhook payload, CAPPED.
	//
	// This is the only unauthenticated route in the service that reads a request
	// body, and it read it unbounded (#744). The read happens before the
	// URL-embedded secret and before the HMAC signature are checked -- it has to,
	// since the signature is computed over the body -- so the only precondition
	// for reaching it was a syntactically valid UUID in the path. The UUID does
	// not even have to name a real link: a non-existent one still reaches this
	// read before the 404 below.
	//
	// With ReadTimeout at 30s and no global body-size middleware anywhere, a
	// handful of concurrent slow POSTs could hold arbitrary heap with zero
	// credentials. Every other body-decode path in this codebase -- SCM API
	// responses, OSV, mirror upstreams, provider uploads -- is already capped;
	// this was the exception, and also the only one reachable anonymously.
	//
	// MaxBytesReader rather than io.LimitReader: LimitReader TRUNCATES silently,
	// which here would mean computing the HMAC over a partial body and rejecting
	// a legitimate large payload as a signature mismatch -- a confusing failure
	// pointing at the wrong cause. MaxBytesReader makes the read itself fail, so
	// an oversized payload is reported as oversized.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxWebhookPayloadBytes)
	payloadBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		// Deliberately does not distinguish "too large" from "read failed" in the
		// response: this endpoint is unauthenticated, and the caller has not yet
		// proved it knows the secret, so it learns nothing about limits here.
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "failed to read payload"})
		return
	}

	// Get the module source repository link.
	// The URL path segment is the link's own id (module_scm_repos.id), not the
	// module_id — so we must look up by id. Using GetModuleSourceRepo (which
	// queries WHERE module_id = $1) would always return nil and produce 404.
	moduleSourceRepo, err := h.scmRepo.GetModuleSourceRepoByID(c.Request.Context(), repoID)
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
	clientSecret, err := h.tokenCipher.Open(provider.ClientSecretEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt client secret"})
		return
	}
	connector, err := scm.BuildConnector(&scm.ConnectorSettings{
		Kind:            provider.ProviderType,
		InstanceBaseURL: baseURL,
		ClientID:        provider.ClientID,
		ClientSecret:    clientSecret,
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

	// Process the webhook asynchronously if it's a tag push.
	// Use a detached context because the request context is cancelled as soon as
	// the HTTP response is sent, but the publishing work (SCM download, storage
	// upload, DB writes) can take minutes.
	if hook.IsTagEvent() && moduleSourceRepo.AutoPublish {
		asyncCtx, asyncCancel := context.WithTimeout(context.Background(), 10*time.Minute) // #nosec G118 -- asyncCancel is called via defer inside the goroutine closure below
		msr := moduleSourceRepo
		h2 := hook
		conn := connector
		safego.Go(func() {
			defer asyncCancel()
			h.publisher.ProcessTagPush(asyncCtx, logID, msr, h2, conn)
		})
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
