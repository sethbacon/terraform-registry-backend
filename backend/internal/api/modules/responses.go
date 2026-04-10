package modules

import "time"

// ModuleUploadResponse is returned by POST /api/v1/modules.
type ModuleUploadResponse struct {
	ID        string    `json:"id"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	System    string    `json:"system"`
	Version   string    `json:"version"`
	Checksum  string    `json:"checksum"`
	SizeBytes int64     `json:"size_bytes"`
	Filename  string    `json:"filename"`
	CreatedAt time.Time `json:"created_at"`
}

// ModuleVersionEntry represents a single version in the module versions list response.
type ModuleVersionEntry struct {
	ID                 string  `json:"id"`
	Version            string  `json:"version"`
	PublishedAt        string  `json:"published_at"`
	DownloadCount      int64   `json:"download_count"`
	Deprecated         bool    `json:"deprecated"`
	DeprecatedAt       *string `json:"deprecated_at,omitempty"`
	DeprecationMessage *string `json:"deprecation_message,omitempty"`
	HasDocs            bool    `json:"has_docs"`
}

// ModuleVersionsModuleItem represents a single module source item in the versions list response.
type ModuleVersionsModuleItem struct {
	Source   *string              `json:"source"`
	Versions []ModuleVersionEntry `json:"versions"`
}

// ModuleVersionsResponse is returned by GET /v1/modules/{namespace}/{name}/{system}/versions.
type ModuleVersionsResponse struct {
	Modules []ModuleVersionsModuleItem `json:"modules"`
}

// LinkModuleSCMResponse is returned by POST /api/v1/admin/modules/{id}/scm.
type LinkModuleSCMResponse struct {
	Message            string `json:"message"`
	LinkID             string `json:"link_id"`
	WebhookCallbackURL string `json:"webhook_callback_url"`
	Note               string `json:"note"`
}

// SearchMetadata carries pagination info for search responses.
type SearchMetadata struct {
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
	Total  int64 `json:"total"`
}

// ModuleSearchItem represents a single module result in search responses.
type ModuleSearchItem struct {
	ID            string    `json:"id"`
	Namespace     string    `json:"namespace"`
	Name          string    `json:"name"`
	System        string    `json:"system"`
	Description   string    `json:"description,omitempty"`
	DownloadCount int64     `json:"download_count"`
	CreatedAt     time.Time `json:"created_at"`
}

// ModuleSearchResponse is returned by GET /api/v1/modules/search.
type ModuleSearchResponse struct {
	Modules []ModuleSearchItem `json:"modules"`
	Meta    SearchMetadata     `json:"meta"`
}
