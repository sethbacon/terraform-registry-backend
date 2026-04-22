package setup

// ValidateTokenResponse is returned by POST /api/v1/setup/validate-token.
type ValidateTokenResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// TestOIDCConfigResponse is returned by POST /api/v1/setup/oidc/test.
type TestOIDCConfigResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Issuer  string `json:"issuer,omitempty"`
}

// TestStorageConfigResponse is returned by POST /api/v1/setup/storage/test.
type TestStorageConfigResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// SaveStorageConfigResponse is returned by POST /api/v1/setup/storage.
type SaveStorageConfigResponse struct {
	Message string      `json:"message"`
	Config  interface{} `json:"config"`
}

// ConfigureAdminResponse is returned by POST /api/v1/setup/admin.
type ConfigureAdminResponse struct {
	Message      string `json:"message"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
	Role         string `json:"role"`
}

// CompleteSetupResponse is returned by POST /api/v1/setup/complete.
type CompleteSetupResponse struct {
	Message        string `json:"message"`
	SetupCompleted bool   `json:"setup_completed"`
}

// TestScanningConfigResponse is returned by POST /api/v1/setup/scanning/test.
type TestScanningConfigResponse struct {
	Success         bool   `json:"success"`
	DetectedVersion string `json:"detected_version,omitempty"`
	Error           string `json:"error,omitempty"`
}

// SaveScanningConfigResponse is returned by POST /api/v1/setup/scanning.
type SaveScanningConfigResponse struct {
	Message string `json:"message"`
}

// InstallScannerResponse is returned by POST /api/v1/setup/scanning/install.
type InstallScannerResponse struct {
	Success    bool   `json:"success"`
	Tool       string `json:"tool,omitempty"`
	Version    string `json:"version,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	Sha256     string `json:"sha256,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
	Error      string `json:"error,omitempty"`
}
