package webhooks

// WebhookReceivedResponse is returned by POST /webhooks/scm/{module_source_repo_id}/{secret}.
type WebhookReceivedResponse struct {
	Message string `json:"message"`
	LogID   string `json:"log_id"`
}
