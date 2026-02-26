// Package config loads and validates the registry configuration using Viper.
//
// Configuration is layered: built-in defaults < YAML config file < environment
// variables. Environment variables use the TFR_ prefix (e.g., TFR_DATABASE_HOST
// overrides database.host in the YAML). This layering allows the same binary to
// run with a config.yaml in local development and with pure environment variables
// in containerized deployments — no recompilation or different binaries needed.
//
// The ENCRYPTION_KEY variable has no TFR_ prefix because it may be injected by
// infrastructure tooling (e.g., Kubernetes secrets, Vault agent) that does not
// know the application-specific prefix and treats it as a generic secret name.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all application configuration
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Auth     AuthConfig     `mapstructure:"auth"`
	// ApiDocs holds OpenAPI/Swagger metadata that can be overridden at deploy-time
	ApiDocs       ApiDocsConfig       `mapstructure:"api_docs"`
	MultiTenancy  MultiTenancyConfig  `mapstructure:"multi_tenancy"`
	Security      SecurityConfig      `mapstructure:"security"`
	Logging       LoggingConfig       `mapstructure:"logging"`
	Telemetry     TelemetryConfig     `mapstructure:"telemetry"`
	Audit         AuditConfig         `mapstructure:"audit"`
	Notifications NotificationsConfig `mapstructure:"notifications"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	BaseURL      string        `mapstructure:"base_url"`
	PublicURL    string        `mapstructure:"public_url"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// GetPublicURL returns the public-facing URL used for OAuth callbacks and external redirects.
// When server.public_url is set it is returned as-is; otherwise it falls back to server.base_url.
// This distinction matters in reverse-proxied deployments where the internal listen address
// (base_url) differs from the URL registered with the OAuth provider (public_url).
func (s *ServerConfig) GetPublicURL() string {
	if s.PublicURL != "" {
		return s.PublicURL
	}
	return s.BaseURL
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Host               string `mapstructure:"host"`
	Port               int    `mapstructure:"port"`
	Name               string `mapstructure:"name"`
	User               string `mapstructure:"user"`
	Password           string `mapstructure:"password"`
	SSLMode            string `mapstructure:"ssl_mode"`
	MaxConnections     int    `mapstructure:"max_connections"`
	MinIdleConnections int    `mapstructure:"min_idle_connections"`
}

// StorageConfig holds storage backend configuration
type StorageConfig struct {
	DefaultBackend string             `mapstructure:"default_backend"`
	Azure          AzureStorageConfig `mapstructure:"azure"`
	S3             S3StorageConfig    `mapstructure:"s3"`
	GCS            GCSStorageConfig   `mapstructure:"gcs"`
	Local          LocalStorageConfig `mapstructure:"local"`
}

// AzureStorageConfig holds Azure Blob Storage configuration
type AzureStorageConfig struct {
	AccountName   string `mapstructure:"account_name"`
	AccountKey    string `mapstructure:"account_key"`
	ContainerName string `mapstructure:"container_name"`
	CDNURL        string `mapstructure:"cdn_url"`
}

// S3StorageConfig holds S3-compatible storage configuration
type S3StorageConfig struct {
	// Endpoint is the S3-compatible endpoint URL (optional, for MinIO, DigitalOcean Spaces, etc.)
	Endpoint string `mapstructure:"endpoint"`
	// Region is the AWS region
	Region string `mapstructure:"region"`
	// Bucket is the S3 bucket name
	Bucket string `mapstructure:"bucket"`

	// Authentication method: "default", "static", "oidc", "assume_role"
	// - "default": Use AWS default credential chain (env vars, shared config, IAM role, etc.)
	// - "static": Use explicit access key and secret key
	// - "oidc": Use Web Identity/OIDC token for authentication (EKS, GitHub Actions, etc.)
	// - "assume_role": Assume an IAM role (optionally with external ID for cross-account)
	AuthMethod string `mapstructure:"auth_method"`

	// Static credentials (when auth_method is "static" or empty for backwards compatibility)
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`

	// AssumeRole configuration (when auth_method is "assume_role" or "oidc")
	RoleARN         string `mapstructure:"role_arn"`
	RoleSessionName string `mapstructure:"role_session_name"`
	ExternalID      string `mapstructure:"external_id"`

	// OIDC/Web Identity configuration (when auth_method is "oidc")
	// WebIdentityTokenFile is the path to the OIDC token file (e.g., from EKS or GitHub Actions)
	WebIdentityTokenFile string `mapstructure:"web_identity_token_file"`
}

// GCSStorageConfig holds Google Cloud Storage configuration
type GCSStorageConfig struct {
	// Bucket is the GCS bucket name
	Bucket string `mapstructure:"bucket"`

	// ProjectID is the Google Cloud project ID (optional if using default credentials)
	ProjectID string `mapstructure:"project_id"`

	// Authentication method: "default", "service_account", "workload_identity"
	// - "default": Use Application Default Credentials (ADC) - recommended for GCP-native deployments
	// - "service_account": Use a service account key file
	// - "workload_identity": Use Workload Identity Federation (GKE, GitHub Actions, etc.)
	AuthMethod string `mapstructure:"auth_method"`

	// CredentialsFile is the path to a service account JSON key file
	// (when auth_method is "service_account")
	CredentialsFile string `mapstructure:"credentials_file"`

	// CredentialsJSON is the service account JSON key as a string
	// (alternative to credentials_file, useful for environment variables)
	CredentialsJSON string `mapstructure:"credentials_json"`

	// Endpoint is an optional custom endpoint (for GCS emulators or compatible services)
	Endpoint string `mapstructure:"endpoint"`
}

// LocalStorageConfig holds local filesystem storage configuration
type LocalStorageConfig struct {
	BasePath      string `mapstructure:"base_path"`
	ServeDirectly bool   `mapstructure:"serve_directly"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	APIKeys APIKeyConfig  `mapstructure:"api_keys"`
	OIDC    OIDCConfig    `mapstructure:"oidc"`
	AzureAD AzureADConfig `mapstructure:"azure_ad"`
}

// APIKeyConfig holds API key authentication configuration
type APIKeyConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Prefix  string `mapstructure:"prefix"`
}

// OIDCGroupMapping maps a single IdP group to an organization and role template.
// Example: group "registry-admins" → org "default" + role "admin".
type OIDCGroupMapping struct {
	Group        string `mapstructure:"group"`
	Organization string `mapstructure:"organization"`
	Role         string `mapstructure:"role"`
}

// OIDCConfig holds generic OIDC provider configuration
type OIDCConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	IssuerURL    string   `mapstructure:"issuer_url"`
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURL  string   `mapstructure:"redirect_url"`
	Scopes       []string `mapstructure:"scopes"`

	// Group-to-role mapping — optional. When set, the IdP group claim is read
	// on every login and used to assign (or update) the user's org membership.
	//
	// GroupClaimName: the JWT claim that contains the user's groups (e.g. "groups").
	// GroupMappings:  list of {group, organization, role} mappings.
	// DefaultRole:    role template to assign when no group matches; leave empty
	//                 to make unmatched users members with no role template.
	GroupClaimName string             `mapstructure:"group_claim_name"`
	GroupMappings  []OIDCGroupMapping `mapstructure:"group_mappings"`
	DefaultRole    string             `mapstructure:"default_role"`
}

// AzureADConfig holds Azure AD specific configuration
type AzureADConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	TenantID     string `mapstructure:"tenant_id"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

// MultiTenancyConfig holds multi-tenancy configuration
type MultiTenancyConfig struct {
	Enabled             bool   `mapstructure:"enabled"`
	DefaultOrganization string `mapstructure:"default_organization"`
	AllowPublicSignup   bool   `mapstructure:"allow_public_signup"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	CORS         CORSConfig         `mapstructure:"cors"`
	RateLimiting RateLimitingConfig `mapstructure:"rate_limiting"`
	TLS          TLSConfig          `mapstructure:"tls"`
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
}

// RateLimitingConfig holds rate limiting configuration
type RateLimitingConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	RequestsPerMinute int  `mapstructure:"requests_per_minute"`
	Burst             int  `mapstructure:"burst"`
}

// TLSConfig holds TLS/HTTPS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// TelemetryConfig holds observability configuration
type TelemetryConfig struct {
	Enabled     bool            `mapstructure:"enabled"`
	ServiceName string          `mapstructure:"service_name"`
	Metrics     MetricsConfig   `mapstructure:"metrics"`
	Tracing     TracingConfig   `mapstructure:"tracing"`
	Profiling   ProfilingConfig `mapstructure:"profiling"`
}

// MetricsConfig holds Prometheus metrics configuration
type MetricsConfig struct {
	Enabled        bool `mapstructure:"enabled"`
	PrometheusPort int  `mapstructure:"prometheus_port"`
}

// TracingConfig holds distributed tracing configuration
type TracingConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	JaegerEndpoint string `mapstructure:"jaeger_endpoint"`
}

// ProfilingConfig holds profiling configuration
type ProfilingConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Port    int  `mapstructure:"port"`
}

// AuditConfig holds audit logging configuration
type AuditConfig struct {
	// Enabled determines if audit logging is active
	Enabled bool `mapstructure:"enabled"`
	// LogReadOperations determines if GET requests should be logged
	LogReadOperations bool `mapstructure:"log_read_operations"`
	// LogFailedRequests determines if failed requests (4xx/5xx) should be logged
	LogFailedRequests bool `mapstructure:"log_failed_requests"`
	// Shippers configures external log shipping
	Shippers []AuditShipperConfig `mapstructure:"shippers"`
}

// AuditShipperConfig holds configuration for a single audit shipper
type AuditShipperConfig struct {
	// Enabled determines if this shipper is active
	Enabled bool `mapstructure:"enabled"`
	// Type is the shipper type (syslog, webhook, file)
	Type string `mapstructure:"type"`
	// Syslog configuration
	Syslog *AuditSyslogConfig `mapstructure:"syslog"`
	// Webhook configuration
	Webhook *AuditWebhookConfig `mapstructure:"webhook"`
	// File configuration
	File *AuditFileConfig `mapstructure:"file"`
}

// AuditSyslogConfig holds syslog shipper configuration
type AuditSyslogConfig struct {
	Network  string `mapstructure:"network"`  // udp, tcp, unix
	Address  string `mapstructure:"address"`  // server address
	Tag      string `mapstructure:"tag"`      // syslog tag
	Facility string `mapstructure:"facility"` // syslog facility
}

// AuditWebhookConfig holds webhook shipper configuration
type AuditWebhookConfig struct {
	URL           string            `mapstructure:"url"`
	Headers       map[string]string `mapstructure:"headers"`
	TimeoutSecs   int               `mapstructure:"timeout_secs"`
	BatchSize     int               `mapstructure:"batch_size"`
	FlushInterval int               `mapstructure:"flush_interval_secs"`
}

// AuditFileConfig holds file shipper configuration
type AuditFileConfig struct {
	Path       string `mapstructure:"path"`
	MaxSizeMB  int    `mapstructure:"max_size_mb"`
	MaxBackups int    `mapstructure:"max_backups"`
}

// ApiDocsConfig holds configurable metadata for the generated OpenAPI/Swagger docs
type ApiDocsConfig struct {
	TermsOfService string `mapstructure:"terms_of_service"`
	ContactName    string `mapstructure:"contact_name"`
	ContactEmail   string `mapstructure:"contact_email"`
	License        string `mapstructure:"license"`
}

// NotificationsConfig holds settings for outbound notification emails
type NotificationsConfig struct {
	// Enabled globally toggles all outbound notification emails. Requires SMTP to be configured.
	Enabled bool `mapstructure:"enabled"`
	// SMTP holds the outbound mail server settings
	SMTP SMTPConfig `mapstructure:"smtp"`
	// APIKeyExpiryWarningDays is how many days before expiry to send the first warning email (default 7)
	APIKeyExpiryWarningDays int `mapstructure:"api_key_expiry_warning_days"`
	// APIKeyExpiryCheckIntervalHours determines how often the expiry check job runs (default 24)
	APIKeyExpiryCheckIntervalHours int `mapstructure:"api_key_expiry_check_interval_hours"`
}

// SMTPConfig holds outbound mail server configuration for notification emails
type SMTPConfig struct {
	// Host is the SMTP server hostname (e.g. smtp.sendgrid.net)
	Host string `mapstructure:"host"`
	// Port is the SMTP server port (587 for STARTTLS, 465 for SMTPS, 25 for plain)
	Port int `mapstructure:"port"`
	// Username for SMTP authentication
	Username string `mapstructure:"username"`
	// Password for SMTP authentication
	Password string `mapstructure:"password"`
	// From is the sender address shown in notification emails
	From string `mapstructure:"from"`
	// UseTLS enables STARTTLS (port 587) or implicit TLS (port 465); false = plain SMTP
	UseTLS bool `mapstructure:"use_tls"`
}

// bindEnvVars explicitly binds environment variables to config keys.
// This is necessary because AutomaticEnv() doesn't work well with nested structs during Unmarshal.
// viper.BindEnv only errors when called with zero keys; since every key here is a non-empty
// hardcoded string, any error indicates a programming bug and is surfaced to the caller.
func bindEnvVars(v *viper.Viper) error {
	keys := []string{
		// Database
		"database.host",
		"database.port",
		"database.name",
		"database.user",
		"database.password",
		"database.ssl_mode",
		"database.max_connections",
		"database.min_idle_connections",

		// Server
		"server.host",
		"server.port",
		"server.base_url",
		"server.public_url",
		"server.read_timeout",
		"server.write_timeout",

		// Storage
		"storage.default_backend",
		"storage.azure.account_name",
		"storage.azure.account_key",
		"storage.azure.container_name",
		"storage.azure.cdn_url",
		"storage.s3.endpoint",
		"storage.s3.region",
		"storage.s3.bucket",
		"storage.s3.auth_method",
		"storage.s3.access_key_id",
		"storage.s3.secret_access_key",
		"storage.s3.role_arn",
		"storage.s3.role_session_name",
		"storage.s3.external_id",
		"storage.s3.web_identity_token_file",
		"storage.gcs.bucket",
		"storage.gcs.project_id",
		"storage.gcs.auth_method",
		"storage.gcs.credentials_file",
		"storage.gcs.credentials_json",
		"storage.gcs.endpoint",
		"storage.local.base_path",
		"storage.local.serve_directly",

		// Auth
		"auth.api_keys.enabled",
		"auth.api_keys.prefix",
		"auth.oidc.enabled",
		"auth.oidc.issuer_url",
		"auth.oidc.client_id",
		"auth.oidc.client_secret",
		"auth.oidc.redirect_url",
		"auth.oidc.scopes",
		"auth.oidc.group_claim_name",
		"auth.oidc.group_mappings",
		"auth.oidc.default_role",
		"auth.azure_ad.enabled",
		"auth.azure_ad.tenant_id",
		"auth.azure_ad.client_id",
		"auth.azure_ad.client_secret",
		"auth.azure_ad.redirect_url",

		// Multi-tenancy
		"multi_tenancy.enabled",
		"multi_tenancy.default_organization",
		"multi_tenancy.allow_public_signup",

		// Security
		"security.cors.allowed_origins",
		"security.cors.allowed_methods",
		"security.rate_limiting.enabled",
		"security.rate_limiting.requests_per_minute",
		"security.rate_limiting.burst",
		"security.tls.enabled",
		"security.tls.cert_file",
		"security.tls.key_file",

		// Logging
		"logging.level",
		"logging.format",
		"logging.output",

		// Telemetry
		"telemetry.enabled",
		"telemetry.service_name",
		"telemetry.metrics.enabled",
		"telemetry.metrics.prometheus_port",
		"telemetry.tracing.enabled",
		"telemetry.tracing.jaeger_endpoint",
		"telemetry.profiling.enabled",
		"telemetry.profiling.port",

		// API docs / OpenAPI metadata
		"api_docs.terms_of_service",
		"api_docs.contact_name",
		"api_docs.contact_email",
		"api_docs.license",

		// Notifications / SMTP
		"notifications.enabled",
		"notifications.smtp.host",
		"notifications.smtp.port",
		"notifications.smtp.username",
		"notifications.smtp.password",
		"notifications.smtp.from",
		"notifications.smtp.use_tls",
		"notifications.api_key_expiry_warning_days",
		"notifications.api_key_expiry_check_interval_hours",
	}
	for _, key := range keys {
		if err := v.BindEnv(key); err != nil {
			return fmt.Errorf("failed to bind env var %q: %w", key, err)
		}
	}
	return nil
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set default values
	setDefaults(v)

	// Set config file path if provided
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for config.yaml in common locations
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/terraform-registry")
	}

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found; use defaults and environment variables
	}

	// Enable environment variable support
	v.SetEnvPrefix("TFR")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Explicitly bind environment variables for nested structures
	// This is necessary because AutomaticEnv() doesn't work well with Unmarshal()
	if err := bindEnvVars(v); err != nil {
		return nil, err
	}

	// Unmarshal configuration
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Expand environment variables in sensitive fields
	cfg.Database.Password = expandEnv(cfg.Database.Password)
	cfg.Storage.Azure.AccountKey = expandEnv(cfg.Storage.Azure.AccountKey)
	cfg.Storage.S3.AccessKeyID = expandEnv(cfg.Storage.S3.AccessKeyID)
	cfg.Storage.S3.SecretAccessKey = expandEnv(cfg.Storage.S3.SecretAccessKey)
	cfg.Auth.OIDC.ClientSecret = expandEnv(cfg.Auth.OIDC.ClientSecret)
	cfg.Auth.AzureAD.ClientSecret = expandEnv(cfg.Auth.AzureAD.ClientSecret)
	cfg.Notifications.SMTP.Password = expandEnv(cfg.Notifications.SMTP.Password)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.base_url", "http://localhost:8080")
	v.SetDefault("server.public_url", "")
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.name", "terraform_registry")
	v.SetDefault("database.user", "registry")
	v.SetDefault("database.ssl_mode", "require")
	v.SetDefault("database.max_connections", 25)
	v.SetDefault("database.min_idle_connections", 5)

	// Storage defaults
	v.SetDefault("storage.default_backend", "local")
	v.SetDefault("storage.local.base_path", "./storage")
	v.SetDefault("storage.local.serve_directly", true)

	// Auth defaults
	v.SetDefault("auth.api_keys.enabled", true)
	v.SetDefault("auth.api_keys.prefix", "tfr_")
	v.SetDefault("auth.oidc.enabled", false)
	v.SetDefault("auth.oidc.scopes", []string{"openid", "email", "profile"})
	v.SetDefault("auth.azure_ad.enabled", false)

	// Multi-tenancy defaults
	v.SetDefault("multi_tenancy.enabled", false)
	v.SetDefault("multi_tenancy.default_organization", "default")
	v.SetDefault("multi_tenancy.allow_public_signup", false)

	// Security defaults
	v.SetDefault("security.cors.allowed_origins", []string{"*"})
	v.SetDefault("security.cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	v.SetDefault("security.rate_limiting.enabled", true)
	v.SetDefault("security.rate_limiting.requests_per_minute", 60)
	v.SetDefault("security.rate_limiting.burst", 10)
	v.SetDefault("security.tls.enabled", false)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")

	// Telemetry defaults
	v.SetDefault("telemetry.enabled", true)
	v.SetDefault("telemetry.service_name", "terraform-registry")
	v.SetDefault("telemetry.metrics.enabled", true)
	v.SetDefault("telemetry.metrics.prometheus_port", 9090)
	v.SetDefault("telemetry.tracing.enabled", false)
	v.SetDefault("telemetry.profiling.enabled", false)
	v.SetDefault("telemetry.profiling.port", 6060)

	// API docs / OpenAPI metadata defaults
	v.SetDefault("api_docs.terms_of_service", "")
	v.SetDefault("api_docs.contact_name", "")
	v.SetDefault("api_docs.contact_email", "")
	v.SetDefault("api_docs.license", "")

	// Notifications defaults
	v.SetDefault("notifications.enabled", false)
	v.SetDefault("notifications.smtp.port", 587)
	v.SetDefault("notifications.smtp.use_tls", true)
	v.SetDefault("notifications.api_key_expiry_warning_days", 7)
	v.SetDefault("notifications.api_key_expiry_check_interval_hours", 24)
}

// expandEnv expands environment variables in the format ${VAR_NAME}
func expandEnv(s string) string {
	return os.ExpandEnv(s)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	if c.Server.BaseURL == "" {
		return fmt.Errorf("server.base_url is required")
	}

	// Validate database
	if c.Database.Host == "" {
		return fmt.Errorf("database.host is required")
	}
	if c.Database.Name == "" {
		return fmt.Errorf("database.name is required")
	}
	if c.Database.User == "" {
		return fmt.Errorf("database.user is required")
	}

	// Validate storage backend
	validBackends := map[string]bool{"azure": true, "s3": true, "gcs": true, "local": true}
	if !validBackends[c.Storage.DefaultBackend] {
		return fmt.Errorf("invalid storage backend: %s (must be azure, s3, gcs, or local)", c.Storage.DefaultBackend)
	}

	// Validate Azure storage if enabled
	if c.Storage.DefaultBackend == "azure" {
		if c.Storage.Azure.AccountName == "" {
			return fmt.Errorf("storage.azure.account_name is required when using Azure backend")
		}
		if c.Storage.Azure.AccountKey == "" {
			return fmt.Errorf("storage.azure.account_key is required when using Azure backend")
		}
		if c.Storage.Azure.ContainerName == "" {
			return fmt.Errorf("storage.azure.container_name is required when using Azure backend")
		}
	}

	// Validate S3 storage if enabled
	if c.Storage.DefaultBackend == "s3" {
		if c.Storage.S3.Bucket == "" {
			return fmt.Errorf("storage.s3.bucket is required when using S3 backend")
		}
		if c.Storage.S3.Region == "" {
			return fmt.Errorf("storage.s3.region is required when using S3 backend")
		}
	}

	// Validate GCS storage if enabled
	if c.Storage.DefaultBackend == "gcs" {
		if c.Storage.GCS.Bucket == "" {
			return fmt.Errorf("storage.gcs.bucket is required when using GCS backend")
		}
	}

	// Validate local storage if enabled
	if c.Storage.DefaultBackend == "local" {
		if c.Storage.Local.BasePath == "" {
			return fmt.Errorf("storage.local.base_path is required when using local backend")
		}
	}

	// Validate OIDC if enabled
	if c.Auth.OIDC.Enabled {
		if c.Auth.OIDC.IssuerURL == "" {
			return fmt.Errorf("auth.oidc.issuer_url is required when OIDC is enabled")
		}
		if c.Auth.OIDC.ClientID == "" {
			return fmt.Errorf("auth.oidc.client_id is required when OIDC is enabled")
		}
		if c.Auth.OIDC.ClientSecret == "" {
			return fmt.Errorf("auth.oidc.client_secret is required when OIDC is enabled")
		}
	}

	// Validate Azure AD if enabled
	if c.Auth.AzureAD.Enabled {
		if c.Auth.AzureAD.TenantID == "" {
			return fmt.Errorf("auth.azure_ad.tenant_id is required when Azure AD is enabled")
		}
		if c.Auth.AzureAD.ClientID == "" {
			return fmt.Errorf("auth.azure_ad.client_id is required when Azure AD is enabled")
		}
		if c.Auth.AzureAD.ClientSecret == "" {
			return fmt.Errorf("auth.azure_ad.client_secret is required when Azure AD is enabled")
		}
	}

	// Validate TLS if enabled
	if c.Security.TLS.Enabled {
		if c.Security.TLS.CertFile == "" {
			return fmt.Errorf("security.tls.cert_file is required when TLS is enabled")
		}
		if c.Security.TLS.KeyFile == "" {
			return fmt.Errorf("security.tls.key_file is required when TLS is enabled")
		}
	}

	// Validate logging level
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("invalid logging level: %s (must be debug, info, warn, or error)", c.Logging.Level)
	}

	return nil
}

// GetDSN returns the PostgreSQL connection string
func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode,
	)
}

// GetAddress returns the server address in host:port format
func (c *ServerConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
