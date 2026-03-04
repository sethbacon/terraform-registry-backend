package providers

// ProviderUploadResponse is returned by POST /api/v1/providers.
type ProviderUploadResponse struct {
	ID        string   `json:"id"`
	Namespace string   `json:"namespace"`
	Type      string   `json:"type"`
	Version   string   `json:"version"`
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	Protocols []string `json:"protocols"`
	Checksum  string   `json:"checksum"`
	SizeBytes int64    `json:"size_bytes"`
	Filename  string   `json:"filename"`
}

// ProviderPlatformEntry represents a single platform in the provider versions list response.
type ProviderPlatformEntry struct {
	ID            string `json:"id"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Filename      string `json:"filename"`
	Shasum        string `json:"shasum"`
	DownloadCount int64  `json:"download_count"`
}

// ProviderVersionEntry represents a single version in the provider versions list response.
type ProviderVersionEntry struct {
	ID                 string                  `json:"id"`
	Version            string                  `json:"version"`
	Protocols          []string                `json:"protocols"`
	Platforms          []ProviderPlatformEntry `json:"platforms"`
	PublishedAt        string                  `json:"published_at"`
	Deprecated         bool                    `json:"deprecated"`
	DownloadCount      int64                   `json:"download_count"`
	DeprecatedAt       *string                 `json:"deprecated_at,omitempty"`
	DeprecationMessage *string                 `json:"deprecation_message,omitempty"`
}

// ProviderVersionsResponse is returned by GET /v1/providers/{namespace}/{type}/versions.
type ProviderVersionsResponse struct {
	Versions []ProviderVersionEntry `json:"versions"`
}

// ProviderSearchItem represents a single provider result in search responses.
type ProviderSearchItem struct {
	ID            string `json:"id"`
	Namespace     string `json:"namespace"`
	Type          string `json:"type"`
	Description   string `json:"description,omitempty"`
	Source        string `json:"source,omitempty"`
	LatestVersion string `json:"latest_version,omitempty"`
	DownloadCount int64  `json:"download_count"`
}

// ProviderSearchMeta carries pagination info for provider search responses.
type ProviderSearchMeta struct {
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
	Total  int64 `json:"total"`
}

// ProviderSearchResponse is returned by GET /api/v1/providers/search.
type ProviderSearchResponse struct {
	Providers []ProviderSearchItem `json:"providers"`
	Meta      ProviderSearchMeta   `json:"meta"`
}

// ProviderSigningKeys holds GPG public key info for provider download responses.
type ProviderSigningKeys struct {
	GPGPublicKeys []ProviderGPGKey `json:"gpg_public_keys"`
}

// ProviderGPGKey represents a single GPG key entry.
type ProviderGPGKey struct {
	KeyID      string `json:"key_id"`
	ASCIIArmor string `json:"ascii_armor"`
}

// ProviderDownloadResponse is returned by GET /v1/providers/{namespace}/{type}/{version}/download/{os}/{arch}.
type ProviderDownloadResponse struct {
	Protocols           []string             `json:"protocols"`
	OS                  string               `json:"os"`
	Arch                string               `json:"arch"`
	Filename            string               `json:"filename"`
	DownloadURL         string               `json:"download_url"`
	ShasumsURL          string               `json:"shasums_url"`
	ShasumsSignatureURL string               `json:"shasums_signature_url"`
	Shasum              string               `json:"shasum"`
	SigningKeys         *ProviderSigningKeys `json:"signing_keys,omitempty"`
}
