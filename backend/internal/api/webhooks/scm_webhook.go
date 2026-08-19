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
	"github.com/terraform-registry/terraform-registry/internal/identityerr"
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

	// orgExists reports whether an SCM provider's owning organization still
	// resolves in the identity store (issue #899).
	//
	// This route is the only UNAUTHENTICATED one that acts on a credential, and
	// until migration 000056 (issue #883) scm_providers.organization_id was
	// ON DELETE CASCADE, so an SCM provider could not outlive its organization
	// and the question never arose. It can now, in every topology, and nothing
	// else on this path asks it: the provider is loaded by id from the payload
	// URL and its webhook_secret is honoured on its own authority.
	//
	// A function rather than a repository: organizations live on the IDENTITY
	// connection, which may be another schema or another database, while
	// everything else this handler touches is the registry's. Closing over the
	// lookup keeps that seam at the wiring site (WithOrganizationExistence)
	// instead of putting a second connection inside the handler.
	//
	// nil means unwired, which skips the check -- the same convention the
	// admin handlers' optional dependencies follow.
	orgExists func(ctx context.Context, orgID string) (bool, error)
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

// WithOrganizationExistence wires the identity-connection lookup that decides
// whether an SCM provider's organization is still there (issue #899).
//
// The repository MUST be built on the identity connection, unlike scmRepo:
// organizations move to the identity schema at cutover and may live in a
// separate database entirely, which is the whole reason no foreign key can
// hold this invariant any more.
//
// OrgScopeAllOrganizations is deliberate and is not an authorization decision.
// The caller here is an SCM server with no principal at all; the question being
// asked is "does this row's owner still exist", which is a platform fact.
func (h *SCMWebhookHandler) WithOrganizationExistence(orgRepo *repositories.OrganizationRepository) *SCMWebhookHandler {
	if orgRepo == nil {
		return h
	}
	h.orgExists = func(ctx context.Context, orgID string) (bool, error) {
		org, err := orgRepo.GetByID(ctx, orgID, repositories.OrgScopeAllOrganizations())
		if identityerr.Missing(org, err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return h
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

	// GUARD webhook-provider-org-exists (issue #899). Refuse to act on an SCM
	// provider whose organization has been deleted.
	//
	// DeleteOrganizationHandler now refuses that deletion, so no NEW orphan can
	// be created through the API -- but this check is what covers the ones that
	// already exist (any deployment that deleted an organization while
	// migration 000056 was in place and this guard was not) and the ones no
	// registry handler is involved in at all, since organizations may live in
	// another database where they can be removed without this service ever
	// seeing the verb.
	//
	// Placed here, after the URL-embedded secret has been verified and before
	// the client secret is decrypted: the caller has already proved it holds
	// the link's secret, so this leaks nothing new, and an orphaned provider's
	// ciphertext is never opened.
	//
	// A zero organization_id is the single-tenant deployment (the column is
	// nullable and google/uuid scans NULL to uuid.Nil), which is owned by no
	// organization and has nothing to check.
	if h.orgExists != nil && provider.OrganizationID != uuid.Nil {
		exists, orgErr := h.orgExists(c.Request.Context(), provider.OrganizationID.String())
		if orgErr != nil {
			// Fail CLOSED. The alternative -- treating a lookup failure as
			// "probably still there" -- publishes into a tenant on the strength
			// of a database error, on an unauthenticated route.
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify SCM provider organization"})
			return
		}
		if !exists {
			// Same answer as a missing provider, deliberately: an orphaned
			// provider is indistinguishable from one that was deleted properly,
			// so this adds no new signal for an anonymous caller.
			c.JSON(http.StatusNotFound, gin.H{"error": "SCM provider not found"})
			return
		}
	}

	// Build connector for this provider
	baseURL := ""
	if provider.BaseURL != nil {
		baseURL = *provider.BaseURL
	}
	clientSecret, _, err := h.tokenCipher.OpenWithContextOrLegacy(
		provider.ClientSecretEncrypted, scm.ProviderClientSecretContext(provider.ID.String()))
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
