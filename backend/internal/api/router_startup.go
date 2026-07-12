// router_startup.go holds cohesive startup phases extracted from NewRouter so
// that function reads as a sequence of named steps rather than one ~1200-line
// god function mixing DB-backed config hot-reload, DI, and routing (issue
// #565 finding [39]). Each helper here does exactly one thing and mutates the
// shared *config.Config in place, matching the inline behavior it replaced.
package api

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/api/setup"
	"github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// reloadScanningConfigFromDB applies any scanning configuration persisted by
// the setup wizard over the file/env config. It has two independent parts,
// preserved exactly from the original inline logic:
//
//   - When scanning is NOT already enabled via config, a persisted+enabled DB
//     config is applied wholesale (after re-validating the tool name, since
//     older rows may carry a non-allowlisted tool that would otherwise flow
//     into filepath.Join(InstallDir, Tool)).
//   - Regardless of the enabled gate, persisted auto-update settings are always
//     reloaded — otherwise admin-configured auto-update would never take effect
//     at boot when scanning is enabled via env/YAML.
func reloadScanningConfigFromDB(cfg *config.Config, repo *repositories.OIDCConfigRepository) {
	// The DB JSON was saved from SaveScanningConfigInput (snake_case json
	// tags), so decode into an anonymous struct with matching json tags
	// rather than config.ScanningConfig which only carries mapstructure tags.
	if !cfg.Scanning.Enabled {
		if scanConfigJSON, err := repo.GetScanningConfig(context.Background()); err == nil && scanConfigJSON != nil {
			var dbInput struct {
				Enabled           bool   `json:"enabled"`
				Tool              string `json:"tool"`
				BinaryPath        string `json:"binary_path"`
				ExpectedVersion   string `json:"expected_version"`
				SeverityThreshold string `json:"severity_threshold"`
				TimeoutSecs       int    `json:"timeout_secs"`
				WorkerCount       int    `json:"worker_count"`
				ScanIntervalMins  int    `json:"scan_interval_mins"`
				InstallDir        string `json:"install_dir"`
			}
			if err := json.Unmarshal(scanConfigJSON, &dbInput); err == nil && dbInput.Enabled {
				if !setup.IsValidScanningTool(dbInput.Tool) {
					log.Printf("scanner startup: refusing to apply DB config with unsupported tool %q; scanning will remain disabled until reconfigured", dbInput.Tool)
				} else {
					cfg.Scanning.Enabled = dbInput.Enabled
					cfg.Scanning.Tool = dbInput.Tool
					cfg.Scanning.BinaryPath = dbInput.BinaryPath
					cfg.Scanning.ExpectedVersion = dbInput.ExpectedVersion
					cfg.Scanning.SeverityThreshold = dbInput.SeverityThreshold
					cfg.Scanning.WorkerCount = dbInput.WorkerCount
					if dbInput.TimeoutSecs > 0 {
						cfg.Scanning.Timeout = time.Duration(dbInput.TimeoutSecs) * time.Second
					}
					if dbInput.ScanIntervalMins > 0 {
						cfg.Scanning.ScanIntervalMins = dbInput.ScanIntervalMins
					}
					if dbInput.InstallDir != "" {
						cfg.Scanning.InstallDir = dbInput.InstallDir
					}
				}
			}
		}
	}

	// Always reload persisted auto-update settings, even when scanning itself
	// is enabled via env/YAML (the gate above only covers scanning.enabled).
	if scanConfigJSON, err := repo.GetScanningConfig(context.Background()); err == nil && scanConfigJSON != nil {
		var dbCfg config.ScanningConfigDB
		if err := json.Unmarshal(scanConfigJSON, &dbCfg); err != nil {
			log.Printf("scanner startup: failed to parse persisted scanning config for auto-update reload: %v", err)
		} else {
			cfg.Scanning.AutoUpdate.Enabled = dbCfg.AutoUpdate.Enabled
			cfg.Scanning.AutoUpdate.IntervalHours = dbCfg.AutoUpdate.IntervalHours
			cfg.Scanning.AutoUpdate.RequiresApproval = dbCfg.AutoUpdate.RequiresApproval
			cfg.Scanning.AutoUpdate.AutoApproveRules = dbCfg.AutoUpdate.AutoApproveRules
		}
	}
}

// reloadNotificationsConfigFromDB applies any notifications configuration
// persisted by the setup wizard on top of the YAML/env defaults, decrypting
// the stored SMTP password via the token cipher (so it must run after the
// cipher is constructed). Fields are set in place on cfg.Notifications (never
// reassigned) so jobs holding &cfg.Notifications observe the reloaded values.
func reloadNotificationsConfigFromDB(cfg *config.Config, repo *repositories.OIDCConfigRepository, tokenCipher *crypto.TokenCipher) {
	njson, err := repo.GetNotificationsConfig(context.Background())
	if err != nil || njson == nil {
		return
	}
	var dbc admin.NotificationsConfigDB
	if err := json.Unmarshal(njson, &dbc); err != nil {
		log.Printf("notifications startup: failed to parse persisted config: %v", err)
		return
	}
	cfg.Notifications.Enabled = dbc.Enabled
	cfg.Notifications.SMTP.Host = dbc.SMTP.Host
	cfg.Notifications.SMTP.Port = dbc.SMTP.Port
	cfg.Notifications.SMTP.Username = dbc.SMTP.Username
	cfg.Notifications.SMTP.From = dbc.SMTP.From
	cfg.Notifications.SMTP.UseTLS = dbc.SMTP.UseTLS
	if dbc.SMTP.PasswordEncrypted != "" {
		if pw, derr := tokenCipher.Open(dbc.SMTP.PasswordEncrypted); derr == nil {
			cfg.Notifications.SMTP.Password = pw
		} else {
			log.Printf("notifications startup: failed to decrypt persisted smtp password: %v", derr)
		}
	}
	if dbc.APIKeyExpiryWarningDays > 0 {
		cfg.Notifications.APIKeyExpiryWarningDays = dbc.APIKeyExpiryWarningDays
	}
	if dbc.APIKeyExpiryCheckIntervalHours > 0 {
		cfg.Notifications.APIKeyExpiryCheckIntervalHours = dbc.APIKeyExpiryCheckIntervalHours
	}
}

// applyPersistedOIDCProvider loads OIDC configuration persisted by the setup
// wizard from the database, decrypts the client secret via the token cipher,
// builds a live OIDC provider, and installs it on authHandlers. DB config
// takes precedence over static config-file settings and lets OIDC work
// without OIDC pre-configured in config.yaml. Any failure is logged and left
// non-fatal (the app still serves without OIDC).
func applyPersistedOIDCProvider(authHandlers *admin.AuthHandlers, repo *repositories.OIDCConfigRepository, tokenCipher *crypto.TokenCipher) {
	activeOIDCCfg, oidcErr := repo.GetActiveOIDCConfig(context.Background())
	if oidcErr != nil || activeOIDCCfg == nil {
		return
	}
	clientSecret, decErr := tokenCipher.Open(activeOIDCCfg.ClientSecretEncrypted)
	if decErr != nil {
		slog.Error("Failed to decrypt OIDC client secret from database", "error", decErr)
		return
	}
	liveCfg := &config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    activeOIDCCfg.IssuerURL,
		ClientID:     activeOIDCCfg.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  activeOIDCCfg.RedirectURL,
		Scopes:       activeOIDCCfg.GetScopes(),
	}
	provider, provErr := oidc.NewOIDCProvider(liveCfg)
	if provErr != nil {
		slog.Error("Failed to initialize OIDC provider from database config", "error", provErr, "issuer", activeOIDCCfg.IssuerURL)
		return
	}
	authHandlers.SetOIDCProvider(provider)
	slog.Info("OIDC provider loaded from database configuration", "issuer", activeOIDCCfg.IssuerURL)
}
