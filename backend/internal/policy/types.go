package policy

// Config holds configuration for the policy engine.
type Config struct {
	Enabled   bool   `mapstructure:"enabled"`
	Mode      string `mapstructure:"mode"`       // "warn" | "block"
	BundleURL string `mapstructure:"bundle_url"` // HTTPS URL for the Rego bundle tarball (HTTP only if allow-listed)
	// BundleSHA256 optionally pins the expected SHA-256 (hex) of the bundle
	// archive. When set, a fetched bundle whose digest does not match is
	// rejected and the previously loaded policies are kept (fail closed).
	BundleSHA256          string `mapstructure:"bundle_sha256"`
	BundleRefreshInterval int    `mapstructure:"bundle_refresh_interval"` // seconds; 0 = no background refresh
}

// PolicyResult is returned by PolicyEngine.Evaluate.
type PolicyResult struct {
	// Allowed is true when no violations were found.
	Allowed bool `json:"allowed"`
	// Mode mirrors the engine's configured enforcement mode.
	Mode string `json:"mode"`
	// Violations contains one entry per deny rule that fired.
	Violations []Violation `json:"violations,omitempty"`
}

// Violation describes a single policy rule that was violated.
type Violation struct {
	// Rule is the Rego rule path that fired (e.g. "data.registry.deny").
	Rule string `json:"rule"`
	// Message is the human-readable description produced by the Rego rule.
	Message string `json:"message"`
}
