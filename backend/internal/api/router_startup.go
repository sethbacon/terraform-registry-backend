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

	identitycrypto "github.com/sethbacon/terraform-suite-identity/identity/crypto"

	"database/sql"
	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/api/setup"
	"github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// buildIdentityTokenCipher constructs the shared identity/crypto.TokenCipher
// instance used by the notification-channel Notifier and its admin handlers.
// It mirrors this repo's own tokenCipher construction (same ENCRYPTION_KEY /
// ENCRYPTION_KEY_PREVIOUS key material, same dual-key rotation support) but
// produces the shared package's type, since the shared identity/notify
// package cannot depend on this repo's internal/crypto package.
func buildIdentityTokenCipher(encryptionKey, encryptionKeyPrevious string) (*identitycrypto.TokenCipher, error) {
	if encryptionKeyPrevious != "" {
		return identitycrypto.NewTokenCipherWithPrevious([]byte(encryptionKey), []byte(encryptionKeyPrevious))
	}
	return identitycrypto.NewTokenCipher([]byte(encryptionKey))
}

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
		if pw, _, derr := tokenCipher.OpenWithContextOrLegacy(
			dbc.SMTP.PasswordEncrypted, models.SystemSettingsSMTPPasswordContext()); derr == nil {
			cfg.Notifications.SMTP.Password = pw
		} else {
			log.Printf("notifications startup: failed to decrypt persisted smtp password: %v", derr)
		}
	}
	if len(dbc.Recipients) > 0 {
		cfg.Notifications.Recipients = dbc.Recipients
	}
	if dbc.Events != nil {
		// A persisted config saved since this feature shipped: use it exactly.
		cfg.Notifications.Events = config.NotificationEventsConfig(*dbc.Events)
	}
	// else: dbc.Events is nil (persisted before this feature existed) — leave
	// cfg.Notifications.Events at its Viper-default (all true), so upgrading
	// never silently disables a notification nobody opted out of.
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
	// The collapsed `err != nil || cfg == nil` absorbs store.ErrNotFound: a
	// deployment with no active OIDC config is the ordinary un-configured case,
	// which this function is documented to treat as "serve without OIDC".
	activeOIDCCfg, oidcErr := repo.GetActiveOIDCConfig(context.Background())
	if oidcErr != nil || activeOIDCCfg == nil {
		return
	}
	clientSecret, _, decErr := tokenCipher.OpenWithContextOrLegacy(
		activeOIDCCfg.ClientSecretCiphertext,
		models.OIDCConfigClientSecretContext(activeOIDCCfg.ID.String()))
	if decErr != nil {
		slog.Error("Failed to decrypt OIDC client secret from database", "error", decErr)
		return
	}
	// GetScopes returns the standard defaults ALONGSIDE its error, so a
	// corrupted scopes column keeps the behaviour it had before v0.24.0 (fall
	// back to openid/email/profile) rather than taking SSO down at startup.
	// What changes is that the fallback is now said out loud — before, a
	// hand-edited column silently narrowed the scopes every login requested.
	scopes, scopesErr := activeOIDCCfg.GetScopes()
	if scopesErr != nil {
		slog.Error("Failed to parse OIDC scopes from database config; falling back to default scopes",
			"error", scopesErr, "issuer", activeOIDCCfg.IssuerURL, "scopes", scopes)
	}
	liveCfg := &config.OIDCConfig{
		Enabled:      true,
		IssuerURL:    activeOIDCCfg.IssuerURL,
		ClientID:     activeOIDCCfg.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  activeOIDCCfg.RedirectURL,
		Scopes:       scopes,
	}
	provider, provErr := oidc.NewOIDCProvider(liveCfg)
	if provErr != nil {
		slog.Error("Failed to initialize OIDC provider from database config", "error", provErr, "issuer", activeOIDCCfg.IssuerURL)
		return
	}
	authHandlers.SetOIDCProvider(provider)
	slog.Info("OIDC provider loaded from database configuration", "issuer", activeOIDCCfg.IssuerURL)
}

// reconcileAuthorizationMirror brings registry's own authorization tables into
// agreement with the identity source, at boot, before any route is built.
//
// Extracted from NewRouter for issue #565 finding [39]. It moved as one piece
// BECAUSE OF THE COMMENT, not despite it: the four steps below are ordered, the
// order is load-bearing, and the reasoning for each is most of what is written
// here. Splitting the prose from the calls it justifies is how the next person
// reorders them.
//
// It returns nothing and assigns nothing the caller uses -- it is pure startup
// side effect, which is what made it separable at all while the rest of
// NewRouter remains a dependency graph.
func reconcileAuthorizationMirror(cfg *config.Config, db, identityDB *sql.DB) {
	// Registry's own per-app authorization tables
	// (sethbacon/terraform-suite-identity#206, migration 000055). SINCE PHASE 3b
	// EVERY ROLE AND EVERY SCOPE SET READ BY THIS PROCESS COMES FROM THEM. The
	// repositories above still dual-write the identity tables, which is what
	// keeps the rollback (deploy the previous image) real.
	//
	// Three startup steps, in this order, and the order is load-bearing.
	//
	// 1. VERIFY, and now FATALLY. The probe asks whether the connection the
	//    repositories resolve `organization_members` through also resolves
	//    registry's two tables. In the default topology it is one connection; under
	//    TFR_IDENTITY_SCHEMA_ENABLED the identity pool's `search_path` resolves
	//    them through its trailing `,public`. The one topology where it cannot is
	//    identity in a SEPARATE DATABASE.
	//
	//    Before the cutover that was logged and survivable: nothing read these
	//    tables, so an unreachable mirror cost only diagnosis. It is not
	//    survivable now. Every authorization decision would be served from a table
	//    this connection cannot see -- which is not "degraded", it is every
	//    principal resolving to no role, i.e. a total outage that presents as a
	//    permissions problem. Refusing to boot is the smaller failure and the one
	//    an operator can act on.
	//
	// 2. RECONCILE, which re-derives registry's tables from the identity source.
	//    It runs on every boot: 000055 ships no SQL backfill (a migration cannot
	//    see which schema or database is live), a re-derivation is a no-op when
	//    nothing changed, and it repairs whatever a transient mirror failure left
	//    behind.
	//
	//    IT IS STILL CORRECT TO RUN IT AFTER THE READ CUTOVER, which is worth
	//    stating because phase 3a's comment predicted the opposite. It would be
	//    wrong if registry's tables were the only record of registry's decisions,
	//    because re-deriving would then overwrite them. They are not: every write
	//    path still writes the identity tables FIRST and mirrors only on success,
	//    so identity is by construction at least as current as the mirror, and
	//    "make the mirror equal identity" can only repair. When phase 4 drops the
	//    dual-write, this call goes with it.
	//
	// 3. SEED registry's own role templates -- AFTER the reconcile, never before.
	//    Step 2 rewrites each template from the identity copy, so a seed that ran
	//    first would be undone on the same boot.
	if vErr := repositories.NewMemberRoleMirror(identityDB).Verify(context.Background()); vErr != nil {
		log.Fatalf("registry's own role tables (migration 000055) are not reachable from the connection "+
			"this process resolves identity reads through, and since terraform-suite-identity#206 phase 3b "+
			"they are where every role and scope set comes from. Booting would serve every principal no role "+
			"at all. This is the separate-identity-database topology (TFR_IDENTITY_DATABASE_*): create "+
			"registry_role_templates and organization_member_roles where that connection can resolve them, "+
			"or run identity in the registry database. Cause: %v", vErr)
	}
	if report, rErr := repositories.ReconcileMemberRoles(context.Background(), identityDB, db); rErr != nil {
		slog.Error("could not reconcile registry's own role tables from the identity source; "+
			"authorization is served from whatever they already hold, and role changes made while the "+
			"live mirror was failing are NOT repaired. Run `role-drift`", "error", rErr)
	} else {
		slog.Info("registry role tables reconciled", "report", report)
	}
	// Registry's role→scope policy, into registry's own table.
	//
	// Gated on EXACTLY the same two conditions as the shared-table seed in
	// cmd/server, and both matter.
	//
	// suite.role_seed_owner, even though registry's own table has no
	// cross-application contention for the flag to arbitrate: while the
	// reconcile above still derives this table from the shared one, seeding one
	// without the other would make the two disagree by construction and leave
	// `role-drift` -- the gate on this whole phase -- permanently non-zero on a
	// deployment that is in fact healthy.
	//
	// The identity-schema CUTOVER, because that is the only topology this seed
	// was ever for. It exists because the shared identity module seeds role
	// templates with identity-core scopes only, so registry layers its own
	// domain scopes on top. In the DEFAULT topology the templates are seeded by
	// registry's own migrations and have been amended by them since, and the
	// reconcile above has already copied that result into this table.
	//
	// THE GO LIST AND THE MIGRATIONS MUST AGREE, and until issue #891 they did
	// not: migration 000018 granted `scanning:read` to `devops` and `auditor`,
	// models.PredefinedRoleTemplates() never carried it, and because the upsert
	// below sets `scopes = EXCLUDED.scopes` this seed REMOVED the scope from
	// both roles on every boot of a cutover deployment. The list now carries it,
	// and internal/db/rolepolicy derives the policy back out of the migration
	// files so a test can require the two to keep agreeing -- in both
	// directions, since the drift that adds a scope no migration granted widens
	// authority instead of narrowing it and does not fail safe.
	//
	// identityDB != db is the cutover test. NewRouter is handed the same handle
	// twice when identity data lives in the app's own schema, and a distinct one
	// exactly when cmd/server opened a dedicated identity pool.
	if identityDB != db && cfg.Suite.ShouldSeedRoles("registry") {
		if sErr := repositories.SeedSystemRoleTemplates(
			context.Background(), db, models.PredefinedRoleTemplates(),
		); sErr != nil {
			slog.Error("could not seed registry's own role templates; roles resolve to whatever "+
				"the reconcile derived from the identity tables", "error", sErr)
		}
	}
	// 4. RECONCILE registry's own group_mappings table from the effective
	//    oidc_config.extra_config lists (terraform-suite-identity#206 phase 2,
	//    migration 000059) -- AFTER steps 2 and 3, because each mirrored row's
	//    role_template_id is resolved against registry_role_templates, which
	//    those steps have just brought current. Same standing-reconcile
	//    reasoning as step 2: 000059 ships no SQL backfill (a migration cannot
	//    see which schema or database holds the live oidc_config rows), a
	//    re-derivation is a no-op when nothing changed, and it repairs whatever
	//    a transient dual-write failure left behind. NOTHING READS THE TABLE
	//    YET, so a failure here is logged, not fatal: requests are unaffected,
	//    only the backfill for the eventual read cutover is stale.
	if report, gErr := repositories.ReconcileGroupMappings(context.Background(), identityDB, db); gErr != nil {
		slog.Error("could not reconcile registry's own group_mappings from oidc_config.extra_config; "+
			"nothing reads the table yet, so requests are unaffected, but the phase-2 backfill is stale "+
			"and mapping changes made while the live dual-write was failing are NOT repaired. Run `role-drift`",
			"error", gErr)
	} else {
		slog.Info("registry group mappings reconciled", "report", report)
	}
	// userTokenRevocationRepo lives on the registry's own domain connection
	// (not identityDB) since it has no FK dependency on the identity schema and
	// must work unchanged whether identity data is in the app's public schema,
	// the shared identity schema, or a separate identity database (issue #559
	// finding [9]).
}
