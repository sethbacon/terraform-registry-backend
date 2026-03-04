package config

import (
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// DatabaseConfig.GetDSN
// ---------------------------------------------------------------------------

func TestGetDSN(t *testing.T) {
	tests := []struct {
		name string
		cfg  DatabaseConfig
		want string
	}{
		{
			name: "standard config",
			cfg: DatabaseConfig{
				Host:     "localhost",
				Port:     5432,
				User:     "registry",
				Password: "secret",
				Name:     "terraform_registry",
				SSLMode:  "require",
			},
			want: "host=localhost port=5432 user=registry password=secret dbname=terraform_registry sslmode=require",
		},
		{
			name: "disable ssl mode",
			cfg: DatabaseConfig{
				Host:     "db.example.com",
				Port:     5433,
				User:     "admin",
				Password: "pass",
				Name:     "mydb",
				SSLMode:  "disable",
			},
			want: "host=db.example.com port=5433 user=admin password=pass dbname=mydb sslmode=disable",
		},
		{
			name: "empty password",
			cfg: DatabaseConfig{
				Host:     "localhost",
				Port:     5432,
				User:     "user",
				Password: "",
				Name:     "dbname",
				SSLMode:  "prefer",
			},
			want: "host=localhost port=5432 user=user password= dbname=dbname sslmode=prefer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.GetDSN()
			if got != tt.want {
				t.Errorf("GetDSN() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ServerConfig.GetAddress
// ---------------------------------------------------------------------------

func TestGetAddress(t *testing.T) {
	tests := []struct {
		name string
		cfg  ServerConfig
		want string
	}{
		{"default", ServerConfig{Host: "0.0.0.0", Port: 8080}, "0.0.0.0:8080"},
		{"localhost", ServerConfig{Host: "localhost", Port: 3000}, "localhost:3000"},
		{"empty host", ServerConfig{Host: "", Port: 8080}, ":8080"},
		{"port 443", ServerConfig{Host: "0.0.0.0", Port: 443}, "0.0.0.0:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.GetAddress()
			if got != tt.want {
				t.Errorf("GetAddress() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Config.Validate
// ---------------------------------------------------------------------------

func minimalValidConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:    8080,
			BaseURL: "http://localhost:8080",
		},
		Database: DatabaseConfig{
			Host: "localhost",
			Name: "terraform_registry",
			User: "registry",
		},
		Storage: StorageConfig{
			DefaultBackend: "local",
			Local:          LocalStorageConfig{BasePath: "./storage"},
		},
		Logging: LoggingConfig{Level: "info"},
	}
}

func TestValidate(t *testing.T) {
	t.Run("valid minimal config passes", func(t *testing.T) {
		if err := minimalValidConfig().Validate(); err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}
	})

	t.Run("invalid server port 0", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Server.Port = 0
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for port 0, got nil")
		}
	})

	t.Run("invalid server port 70000", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Server.Port = 70000
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for port 70000, got nil")
		}
	})

	t.Run("missing base_url", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Server.BaseURL = ""
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for empty base_url, got nil")
		}
	})

	t.Run("missing database host", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Database.Host = ""
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for empty database host, got nil")
		}
	})

	t.Run("missing database name", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Database.Name = ""
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for empty database name, got nil")
		}
	})

	t.Run("missing database user", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Database.User = ""
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for empty database user, got nil")
		}
	})

	t.Run("invalid storage backend", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Storage.DefaultBackend = "ftp"
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for invalid storage backend, got nil")
		}
	})

	t.Run("azure backend missing account_name", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Storage.DefaultBackend = "azure"
		cfg.Storage.Azure = AzureStorageConfig{AccountKey: "key", ContainerName: "c"}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing azure account_name, got nil")
		}
	})

	t.Run("azure backend missing account_key", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Storage.DefaultBackend = "azure"
		cfg.Storage.Azure = AzureStorageConfig{AccountName: "name", ContainerName: "c"}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing azure account_key, got nil")
		}
	})

	t.Run("azure backend missing container_name", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Storage.DefaultBackend = "azure"
		cfg.Storage.Azure = AzureStorageConfig{AccountName: "name", AccountKey: "key"}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing azure container_name, got nil")
		}
	})

	t.Run("valid azure config passes", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Storage.DefaultBackend = "azure"
		cfg.Storage.Azure = AzureStorageConfig{
			AccountName:   "myaccount",
			AccountKey:    "mykey",
			ContainerName: "mycontainer",
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() unexpected error for valid azure config: %v", err)
		}
	})

	t.Run("s3 backend missing bucket", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Storage.DefaultBackend = "s3"
		cfg.Storage.S3 = S3StorageConfig{Region: "us-east-1"}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing s3 bucket, got nil")
		}
	})

	t.Run("s3 backend missing region", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Storage.DefaultBackend = "s3"
		cfg.Storage.S3 = S3StorageConfig{Bucket: "mybucket"}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing s3 region, got nil")
		}
	})

	t.Run("gcs backend missing bucket", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Storage.DefaultBackend = "gcs"
		cfg.Storage.GCS = GCSStorageConfig{}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing gcs bucket, got nil")
		}
	})

	t.Run("local backend missing base_path", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Storage.DefaultBackend = "local"
		cfg.Storage.Local = LocalStorageConfig{BasePath: ""}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing local base_path, got nil")
		}
	})

	t.Run("oidc enabled missing issuer_url", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Auth.OIDC = OIDCConfig{
			Enabled:      true,
			ClientID:     "id",
			ClientSecret: "secret",
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing oidc issuer_url, got nil")
		}
	})

	t.Run("oidc enabled missing client_id", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Auth.OIDC = OIDCConfig{
			Enabled:      true,
			IssuerURL:    "https://accounts.example.com",
			ClientSecret: "secret",
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing oidc client_id, got nil")
		}
	})

	t.Run("oidc enabled all fields valid", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Auth.OIDC = OIDCConfig{
			Enabled:      true,
			IssuerURL:    "https://accounts.example.com",
			ClientID:     "my-client",
			ClientSecret: "my-secret",
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() unexpected error for valid oidc config: %v", err)
		}
	})

	t.Run("azure_ad enabled missing tenant_id", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Auth.AzureAD = AzureADConfig{
			Enabled:      true,
			ClientID:     "id",
			ClientSecret: "secret",
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing azure_ad tenant_id, got nil")
		}
	})

	t.Run("tls enabled missing cert_file", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Security.TLS = TLSConfig{Enabled: true, KeyFile: "key.pem"}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing tls cert_file, got nil")
		}
	})

	t.Run("tls enabled missing key_file", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Security.TLS = TLSConfig{Enabled: true, CertFile: "cert.pem"}
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for missing tls key_file, got nil")
		}
	})

	t.Run("invalid log level", func(t *testing.T) {
		cfg := minimalValidConfig()
		cfg.Logging.Level = "verbose"
		if err := cfg.Validate(); err == nil {
			t.Error("Validate() expected error for invalid log level, got nil")
		}
	})

	t.Run("all valid log levels pass", func(t *testing.T) {
		for _, level := range []string{"debug", "info", "warn", "error"} {
			cfg := minimalValidConfig()
			cfg.Logging.Level = level
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() unexpected error for log level %q: %v", level, err)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Load – defaults and env var expansion
// ---------------------------------------------------------------------------

func TestLoad_DefaultsWithNoFile(t *testing.T) {
	// Load with a nonexistent config path falls back to defaults + env vars
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		// Validation may fail due to missing required fields in default config;
		// that is acceptable – we just check that a file-not-found doesn't crash.
		if !strings.Contains(err.Error(), "invalid configuration") &&
			!strings.Contains(err.Error(), "error reading config file") {
			t.Fatalf("Load() unexpected error kind: %v", err)
		}
	} else {
		// If it did succeed, the defaults should be sensible.
		if cfg.Server.Port != 8080 {
			t.Errorf("default server port = %d, want 8080", cfg.Server.Port)
		}
		if cfg.Database.Host != "localhost" {
			t.Errorf("default database host = %q, want %q", cfg.Database.Host, "localhost")
		}
	}
}

// ---------------------------------------------------------------------------
// expandEnv
// ---------------------------------------------------------------------------

func TestExpandEnv(t *testing.T) {
	t.Run("expands ${VAR} syntax", func(t *testing.T) {
		t.Setenv("CONFIG_TEST_SECRET", "super-secret")
		got := expandEnv("${CONFIG_TEST_SECRET}")
		if got != "super-secret" {
			t.Errorf("expandEnv() = %q, want %q", got, "super-secret")
		}
	})

	t.Run("expands $VAR syntax", func(t *testing.T) {
		t.Setenv("CONFIG_TEST_VAL", "hello")
		got := expandEnv("$CONFIG_TEST_VAL")
		if got != "hello" {
			t.Errorf("expandEnv() = %q, want %q", got, "hello")
		}
	})

	t.Run("plain string passthrough", func(t *testing.T) {
		got := expandEnv("no-vars-here")
		if got != "no-vars-here" {
			t.Errorf("expandEnv() = %q, want %q", got, "no-vars-here")
		}
	})

	t.Run("unset variable expands to empty string", func(t *testing.T) {
		os.Unsetenv("CONFIG_TEST_DEFINITELY_UNSET_12345")
		got := expandEnv("${CONFIG_TEST_DEFINITELY_UNSET_12345}")
		if got != "" {
			t.Errorf("expandEnv() = %q, want empty string", got)
		}
	})

	t.Run("empty string passthrough", func(t *testing.T) {
		got := expandEnv("")
		if got != "" {
			t.Errorf("expandEnv() = %q, want empty string", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Load – with config file
// ---------------------------------------------------------------------------

// writeTempConfig creates a temp YAML file and registers a cleanup to remove it.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "config-test-*.yaml")
	if err != nil {
		t.Fatal("CreateTemp:", err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.WriteString(content); err != nil {
		t.Fatal("WriteString:", err)
	}
	f.Close()
	return f.Name()
}

func TestLoad_WithConfigFile(t *testing.T) {
	const content = `
server:
  host: "testhost"
  port: 9999
  base_url: "http://testhost:9999"
database:
  host: "dbhost"
  name: "testdb"
  user: "testuser"
storage:
  default_backend: "local"
  local:
    base_path: "./test-storage"
logging:
  level: "debug"
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Host != "testhost" {
		t.Errorf("Server.Host = %q, want testhost", cfg.Server.Host)
	}
	if cfg.Server.Port != 9999 {
		t.Errorf("Server.Port = %d, want 9999", cfg.Server.Port)
	}
	if cfg.Database.Host != "dbhost" {
		t.Errorf("Database.Host = %q, want dbhost", cfg.Database.Host)
	}
	if cfg.Database.Name != "testdb" {
		t.Errorf("Database.Name = %q, want testdb", cfg.Database.Name)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want debug", cfg.Logging.Level)
	}
}

func TestLoad_DefaultsApplied(t *testing.T) {
	// Config without server.host or server.port — setDefaults() should fill them in.
	const content = `
server:
  base_url: "http://localhost:8080"
database:
  host: "localhost"
  name: "terraform_registry"
  user: "registry"
storage:
  default_backend: "local"
  local:
    base_path: "./storage"
logging:
  level: "info"
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("default Server.Port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("default Server.Host = %q, want 0.0.0.0", cfg.Server.Host)
	}
	if cfg.Database.Port != 5432 {
		t.Errorf("default Database.Port = %d, want 5432", cfg.Database.Port)
	}
	if cfg.Database.SSLMode != "require" {
		t.Errorf("default Database.SSLMode = %q, want require", cfg.Database.SSLMode)
	}
	if cfg.Auth.APIKeys.Prefix != "tfr_" {
		t.Errorf("default Auth.APIKeys.Prefix = %q, want tfr_", cfg.Auth.APIKeys.Prefix)
	}
	if !cfg.Auth.APIKeys.Enabled {
		t.Error("default Auth.APIKeys.Enabled = false, want true")
	}
}

func TestLoad_EnvVarExpansion(t *testing.T) {
	t.Setenv("TEST_DB_PASS", "mysecret")
	const content = `
server:
  port: 8080
  base_url: "http://localhost:8080"
database:
  host: "localhost"
  name: "terraform_registry"
  user: "registry"
  password: "${TEST_DB_PASS}"
storage:
  default_backend: "local"
  local:
    base_path: "./storage"
logging:
  level: "info"
`
	path := writeTempConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Database.Password != "mysecret" {
		t.Errorf("Database.Password = %q, want mysecret", cfg.Database.Password)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "server: [unclosed")
	_, err := Load(path)
	if err == nil {
		t.Error("Load() expected error for invalid YAML, got nil")
	}
}

// ---------------------------------------------------------------------------
// ServerConfig.GetPublicURL
// ---------------------------------------------------------------------------

func TestGetPublicURL_WithPublicURL(t *testing.T) {
	s := ServerConfig{PublicURL: "https://public.example.com", BaseURL: "http://internal:8080"}
	if got := s.GetPublicURL(); got != "https://public.example.com" {
		t.Errorf("GetPublicURL = %q, want %q", got, "https://public.example.com")
	}
}

func TestGetPublicURL_FallbackToBaseURL(t *testing.T) {
	s := ServerConfig{BaseURL: "http://internal:8080"}
	if got := s.GetPublicURL(); got != "http://internal:8080" {
		t.Errorf("GetPublicURL = %q, want %q", got, "http://internal:8080")
	}
}

func TestGetPublicURL_BothEmpty(t *testing.T) {
	s := ServerConfig{}
	if got := s.GetPublicURL(); got != "" {
		t.Errorf("GetPublicURL = %q, want empty", got)
	}
}
