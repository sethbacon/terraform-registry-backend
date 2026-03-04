package api

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ReadinessChecks contains individual subsystem health results.
type ReadinessChecks struct {
	Database string `json:"database"`
	Storage  string `json:"storage"`
}

// ReadinessResponse is returned by GET /ready.
type ReadinessResponse struct {
	Ready  bool            `json:"ready"`
	Checks ReadinessChecks `json:"checks"`
	Time   string          `json:"time,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// ServiceDiscoveryResponse is returned by GET /.well-known/terraform.json.
type ServiceDiscoveryResponse struct {
	ModulesV1   string `json:"modules.v1"`
	ProvidersV1 string `json:"providers.v1"`
}

// ProtocolVersions lists supported protocol versions by resource type.
type ProtocolVersions struct {
	Modules   string `json:"modules"`
	Providers string `json:"providers"`
	Mirror    string `json:"mirror"`
}

// VersionResponse is returned by GET /version.
type VersionResponse struct {
	Version    string           `json:"version"`
	APIVersion string           `json:"api_version"`
	Protocols  ProtocolVersions `json:"protocols"`
}
