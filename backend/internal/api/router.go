// Package api wires together all HTTP routes for the Terraform Registry backend.
//
// Route grouping philosophy:
//   - Terraform protocol routes (/v1/modules/, /v1/providers/, /v1/mirror/) are
//     intentionally unauthenticated. The HashiCorp protocol specification requires
//     these to be publicly accessible so that `terraform init` can resolve modules
//     and providers without supplying credentials at the discovery stage.
//   - Admin and upload routes (/api/v1/) always require authentication and the
//     appropriate RBAC scope.
//
// The Swagger UI at /api-docs/ is served from embedded static assets (no CDN
// dependency). A per-request nonce allows the inline initialization script to
// execute while keeping the CSP strict for all other content.
package api

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/sethbacon/terraform-suite-identity/identity/auditoutbox"
	identityhttpsafe "github.com/sethbacon/terraform-suite-identity/identity/httpsafe"
	identitymailer "github.com/sethbacon/terraform-suite-identity/identity/mailer"
	identitynotify "github.com/sethbacon/terraform-suite-identity/identity/notify"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
	idstore "github.com/sethbacon/terraform-suite-identity/identity/store"

	"github.com/terraform-registry/terraform-registry/internal/adminfloor"
	"github.com/terraform-registry/terraform-registry/internal/api/admin"
	"github.com/terraform-registry/terraform-registry/internal/api/modules"
	"github.com/terraform-registry/terraform-registry/internal/api/oci"
	"github.com/terraform-registry/terraform-registry/internal/api/setup"
	terraform_binaries "github.com/terraform-registry/terraform-registry/internal/api/terraform_binaries"
	"github.com/terraform-registry/terraform-registry/internal/api/webhooks"
	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/auth"
	"github.com/terraform-registry/terraform-registry/internal/auth/mtls"
	"github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/credlifecycle"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/db/models"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/jobs"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
	"github.com/terraform-registry/terraform-registry/internal/notify"
	"github.com/terraform-registry/terraform-registry/internal/policy"
	"github.com/terraform-registry/terraform-registry/internal/scm"
	"github.com/terraform-registry/terraform-registry/internal/scm/appcreds"
	"github.com/terraform-registry/terraform-registry/internal/services"
	"github.com/terraform-registry/terraform-registry/internal/storage"

	// Import storage backends to register them
	_ "github.com/terraform-registry/terraform-registry/internal/storage/azure"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/gcs"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/local"
	_ "github.com/terraform-registry/terraform-registry/internal/storage/s3"

	// Import SCM connectors to register them via init()
	_ "github.com/terraform-registry/terraform-registry/internal/scm/azuredevops"
	_ "github.com/terraform-registry/terraform-registry/internal/scm/bitbucket"
	_ "github.com/terraform-registry/terraform-registry/internal/scm/github"
	_ "github.com/terraform-registry/terraform-registry/internal/scm/gitlab"
)

// platformAdminTable is the carrier table this application's platform-admin
// mechanism addresses (migration 000051). Unqualified, so the connection's
// search_path places it — the same resolution the hand-written statements had
// before the mechanism moved into the shared library, which is why the swap
// needs no migration.
//
// ONE SPELLING. platformadmin derives the carrier's advisory-lock key from this
// name, so a process constructing it as "public.platform_admins" would address
// the same table under a different lock and lose the serialisation between the
// two.
const platformAdminTable = "platform_admins"

// BackgroundServices holds references to background jobs and resources that must
// be stopped during graceful shutdown. The caller (cmd/server) is responsible for
// calling Shutdown() when the process receives a termination signal.
type BackgroundServices struct {
	// jobs holds every background job behind the jobs.Job interface so they
	// start and stop uniformly (issue #565 finding [40]) instead of via a
	// hand-maintained field-per-job list.
	jobs               *jobs.Registry
	rateLimiters       []middleware.RateLimiterBackend
	principalOverrides *middleware.PrincipalOverrideLimiters
	// auditShipper is non-nil only when cfg.Audit.Shippers configured at least
	// one active shipper (issue #659). Closed on shutdown so a batching
	// WebhookShipper flushes its remaining entries and a FileShipper closes
	// its file handle, rather than being abandoned mid-process-exit.
	auditShipper audit.Shipper
}

// Shutdown stops all background goroutines. It should be called after the HTTP
// server has been shut down so that in-flight requests are drained first.
// coverage:skip:integration-only — requires a running router with live DB and jobs
func (bg *BackgroundServices) Shutdown() {
	slog.Info("stopping background services")
	if bg.jobs != nil {
		bg.jobs.StopAll()
	}
	for _, rl := range bg.rateLimiters {
		if rl != nil {
			_ = rl.Close()
		}
	}
	if bg.principalOverrides != nil {
		_ = bg.principalOverrides.Close()
	}
	if bg.auditShipper != nil {
		if err := bg.auditShipper.Close(); err != nil {
			slog.Error("failed to close audit shipper", "error", err)
		}
	}
	slog.Info("all background services stopped")
}

// collectRateLimiterBackends returns a slice of non-nil rate limiter backends for shutdown tracking.
func collectRateLimiterBackends(backends ...middleware.RateLimiterBackend) []middleware.RateLimiterBackend {
	var out []middleware.RateLimiterBackend
	for _, b := range backends {
		if b != nil {
			out = append(out, b)
		}
	}
	return out
}

// AppVersion, AppBuildDate, and AppCryptoMode are set by main before NewRouter
// is called. They are populated from ldflags injected by GoReleaser at release time.
var AppVersion = "dev"
var AppBuildDate = "unknown"
var AppCryptoMode = "standard"

// NewRouter creates and configures the Gin router.
// coverage:skip:integration-only — wires all repos, jobs, and services together; tested via E2E
// identityDB backs identity data access (users, organizations, API keys, OIDC
// config, audit logs, role templates, revoked tokens). It equals db unless the
// identity-schema cutover is enabled, in which case it targets the shared
// identity schema (feature tables fall back to public via search_path).
func NewRouter(cfg *config.Config, db, identityDB *sql.DB) (*gin.Engine, *BackgroundServices) {
	router := gin.New()
	if err := router.SetTrustedProxies(cfg.Server.TrustedProxies); err != nil {
		log.Fatalf("invalid trusted_proxies config: %v", err)
	}

	// egressGuard widens the SSRF deny-list enforced by every outbound client
	// this router wires up (mirror sync, SCM connectors, OSV poller, policy
	// bundle, SAML metadata, ...) per security.egress.allowlist. Config.Validate
	// already parsed this list once at Load(); a second parse error here would
	// mean cfg was constructed without going through config.Load.
	egressGuard, err := httpsafe.NewGuard(cfg.Security.Egress.Allowlist)
	if err != nil {
		log.Fatalf("invalid security.egress.allowlist: %v", err)
	}
	if err := scm.ConfigureEgress(cfg.Security.Egress.Allowlist); err != nil {
		log.Fatalf("failed to configure SCM connector egress policy: %v", err)
	}
	// Same allow-list, applied to the OIDC discovery/JWKS/token-exchange traffic
	// the shared identity module now routes through its own guard (v0.25.0).
	// Without this an internal IdP — every self-hosted Keycloak/ADFS, and every
	// local compose stack — is denied at provider construction. It runs here,
	// beside the SCM call, so both are configured before any route is built.
	if err := oidc.ConfigureEgress(cfg.Security.Egress.Allowlist); err != nil {
		log.Fatalf("failed to configure OIDC egress policy: %v", err)
	}

	// Construct the real audit external-shipping subsystem from cfg.Audit so
	// AuditMiddlewareWithShipper below is no longer wired up with hardcoded
	// nils (issue #659): previously audit.NewMultiShipperWithGuard's
	// WebhookShipper/SyslogShipper/FileShipper were fully implemented but
	// unreachable dead code, and cfg.Audit.LogReadOperations/LogFailedRequests
	// were silently ignored regardless of what an operator configured.
	auditShipperMS, err := audit.NewMultiShipperFromConfig(cfg.Audit.Shippers, egressGuard)
	if err != nil {
		log.Fatalf("invalid audit.shippers config: %v", err)
	}
	var auditShipper audit.Shipper
	if auditShipperMS.Len() > 0 {
		auditShipper = auditShipperMS
		slog.Info("audit external shipping active", "shippers", auditShipperMS.Len())
	} else if len(cfg.Audit.Shippers) > 0 {
		slog.Warn("audit.shippers is configured but no shipper is active (all disabled, or unsupported on this platform); external audit shipping is a no-op")
	}

	// Initialize storage backend
	storageBackend, err := storage.NewStorage(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize storage backend: %v", err)
	}
	log.Printf("Initialized storage backend: %s", cfg.Storage.DefaultBackend)

	// Identity repositories use identityDB so they follow the configured identity
	// schema; feature repositories below stay on db (public schema).
	userRepo := repositories.NewUserRepository(identityDB)
	apiKeyRepo := repositories.NewAPIKeyRepository(identityDB)
	moduleRepo := repositories.NewModuleRepository(db)
	providerRepo := repositories.NewProviderRepository(db)
	auditRepo := repositories.NewAuditRepository(identityDB)
	orgRepo := repositories.NewOrganizationRepository(identityDB)
	tokenRepo := repositories.NewTokenRepository(identityDB)
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
	// userTokenRevocationRepo lives on the registry's own domain connection
	// (not identityDB) since it has no FK dependency on the identity schema and
	// must work unchanged whether identity data is in the app's public schema,
	// the shared identity schema, or a separate identity database (issue #559
	// finding [9]).
	userTokenRevocationRepo := repositories.NewUserTokenRevocationRepository(db)
	// platformAdminCarrier is the carrier for platform-admin authority outside
	// organization_members (issue #766, migration 000051), and since
	// terraform-suite-identity#206 the mechanism is the shared library's,
	// instantiated against THIS application's table. Same connection and same
	// reasoning as userTokenRevocationRepo above: no FK dependency on the
	// identity schema, so it works unchanged whether identity data is in the
	// app's public schema, the shared identity schema, or a separate identity
	// database.
	//
	// The name is unqualified and is spelled ONCE, here. The library derives
	// the carrier's advisory-lock key from it, so a second spelling elsewhere
	// ("public.platform_admins") would address one table under two locks and
	// lose the serialisation between them.
	platformAdminCarrier, err := platformadmin.New(db, platformAdminTable)
	if err != nil {
		log.Fatalf("failed to construct the platform-admin carrier: %v", err)
	}
	// Reported, not assumed. The table is this application's, in whatever
	// schema this connection's search_path resolves to, and the assertion
	// covers the unique index on user_id as well as the columns: a carrier
	// table with every expected column but no arbiter for
	// ON CONFLICT (user_id) passes every column check and then fails EVERY
	// grant at write time. Logged rather than fatal because a deployment
	// mid-migration must still be able to boot and report why.
	if resolved, vErr := platformAdminCarrier.VerifyTable(context.Background()); vErr != nil {
		slog.Error("platform-admin carrier table did not verify; grants and revocations will fail until it does",
			"table", platformAdminTable, "error", vErr)
	} else {
		slog.Info("platform-admin carrier table verified", "table", resolved)
	}
	// adminFloor holds the two never-zero administrator invariants (issue
	// #766): the deployment always has a platform administrator, and an
	// organization with members always has one of its own.
	//
	// Built here, from BOTH connections, and injected into every handler that
	// can reduce administrative authority. It cannot be constructed inside any
	// of them: platform_admins is on the registry's connection (see
	// platformAdminCarrier above) while organization_members, role_templates and
	// users are on identity's, and under TFR_IDENTITY_DATABASE_* those are
	// different physical databases. Same shape, and the same reason, as
	// credSweeper below.
	adminFloor := adminfloor.New(platformAdminCarrier, identityDB)

	// Namespace ownership claims back the object-level authorization on every
	// module/provider mutation route (issue #555, CWE-639): a namespace binds
	// to the organization that first publishes into it, and only principals
	// with write access in that organization (or admins) may mutate its
	// artifacts. The authorizer is wired per-route below, after RequireScope.
	nsClaimRepo := repositories.NewNamespaceClaimRepository(db)
	nsAuthz := middleware.NewNamespaceAuthorizer(orgRepo, nsClaimRepo, moduleRepo, providerRepo)

	// Wrap *sql.DB with sqlx for SCM and mirror repositories (public) and identity
	// data access (the identity schema when the cutover is enabled).
	sqlxDB := sqlx.NewDb(db, "postgres")
	identitySqlxDB := sqlx.NewDb(identityDB, "postgres")
	scmRepo := repositories.NewSCMRepository(sqlxDB)
	mirrorRepo := repositories.NewMirrorRepository(sqlxDB)
	storageConfigRepo := repositories.NewStorageConfigRepository(sqlxDB)
	// OIDC-config CRUD follows the identity schema; setup-wizard state stays public.
	oidcConfigRepo := repositories.NewOIDCConfigRepositoryWithIdentity(sqlxDB, identitySqlxDB)

	providerDocsRepo := repositories.NewProviderDocsRepository(db)
	scanRepo := repositories.NewModuleScanRepository(db)
	moduleDocsRepo := repositories.NewModuleDocsRepository(db)

	// Initialize pull-through caching service
	pullThroughSvc := services.NewPullThroughService(providerRepo, mirrorRepo, orgRepo)
	pullThroughSvc.SetEgressGuard(egressGuard)

	// jobRegistry collects every background job; they are all started together
	// via StartAll near the end of NewRouter (after full wiring) and stopped
	// together by BackgroundServices.Shutdown (issue #565 finding [40]).
	jobRegistry := jobs.NewRegistry()

	// Initialize mirror sync job - checks every 10 minutes for mirrors needing sync.
	mirrorSyncJob := jobs.NewMirrorSyncJob(mirrorRepo, providerRepo, providerDocsRepo, orgRepo, storageBackend, cfg.Storage.DefaultBackend)
	mirrorSyncJob.SetApprovalRepo(repositories.NewVersionApprovalRepository(sqlxDB))
	mirrorSyncJob.SetEgressGuard(egressGuard)
	mirrorSyncJob.SetInterval(10)
	jobRegistry.Register(mirrorSyncJob)

	// Initialize Terraform binary mirror repository and sync job
	tfMirrorRepo := repositories.NewTerraformMirrorRepository(sqlxDB)
	tfMirrorSyncJob := jobs.NewTerraformMirrorSyncJob(tfMirrorRepo, storageBackend, cfg.Storage.DefaultBackend)
	tfMirrorSyncJob.SetEgressGuard(egressGuard)
	tfMirrorSyncJob.SetInterval(10)
	jobRegistry.Register(tfMirrorSyncJob)

	// Initialize and start the upstream release-signing GPG key refresh job.
	// On success it installs itself as the in-process resolver consulted by
	// terraform mirror sync, so the next sync tick after a successful refresh
	// uses the cached upstream key instead of the embedded snapshot.
	releasesKeyRepo := repositories.NewReleasesGPGKeyRepository(sqlxDB)
	releasesKeyHTTPClient := httpsafe.NewClient(30*time.Second, egressGuard)
	releasesKeyRefreshJob, releasesKeyJobErr := jobs.NewReleasesKeyRefreshJob(&cfg.ReleasesGPGKeys, releasesKeyRepo, releasesKeyHTTPClient)
	if releasesKeyJobErr != nil {
		// The only way construction fails is a parse error on the embedded
		// OpenTofu snapshot — fatal because the fingerprint pin can't be
		// derived. Log and continue without auto-refresh; the embedded
		// fallback still works.
		log.Printf("Releases key refresh job: construction failed: %v (auto-refresh disabled)", releasesKeyJobErr)
	} else {
		jobs.SetReleasesKeyResolver(releasesKeyRefreshJob)
		jobRegistry.Register(releasesKeyRefreshJob)
	}

	// Public handler is created here (before route registration)
	tfBinariesHandler := terraform_binaries.NewHandler(tfMirrorRepo, storageBackend, auditRepo)

	// OCI distribution handler (public read, backed by existing module storage)
	ociHandler := oci.NewHandler(db, storageBackend)

	// Initialize the API key expiry notifier. The shared identity/notify job
	// re-reads notificationsExpiryConfig() on every tick, so an admin toggling
	// notifications.events.api_key_expiring off via the admin API takes effect
	// on the next tick without a process restart (mirrors the pre-shared
	// behavior of holding cfg.Notifications by pointer).
	notificationsExpiryConfig := func() identitynotify.ExpiryConfig {
		return identitynotify.ExpiryConfig{
			Enabled:        cfg.Notifications.Enabled,
			APIKeyExpiring: cfg.Notifications.Events.APIKeyExpiring,
			SMTP: identitymailer.Config{
				Host:     cfg.Notifications.SMTP.Host,
				Port:     cfg.Notifications.SMTP.Port,
				From:     cfg.Notifications.SMTP.From,
				Username: cfg.Notifications.SMTP.Username,
				Password: cfg.Notifications.SMTP.Password,
				// The repo's own use_tls boolean is unchanged (YAML, the
				// persisted settings blob and the admin API body all still carry
				// it); TLSModeForUseTLS is the single tested place that maps it
				// onto mailer.Config's tri-state, whose zero value now encrypts.
				TLSMode: identitymailer.TLSModeForUseTLS(cfg.Notifications.SMTP.UseTLS),
			},
			WarningDays:        cfg.Notifications.APIKeyExpiryWarningDays,
			CheckIntervalHours: cfg.Notifications.APIKeyExpiryCheckIntervalHours,
		}
	}
	expiryNotifier := identitynotify.NewAPIKeyExpiryNotifier(apiKeyRepo, userRepo, notificationsExpiryConfig, identitynotify.ExpiryOptions{ProductName: "Terraform Registry"})
	jobRegistry.Register(expiryNotifier)

	// Apply any scanning configuration persisted by the setup wizard (over the
	// file/env config) before constructing the scanner job, which reads
	// cfg.Scanning at build time. See reloadScanningConfigFromDB.
	reloadScanningConfigFromDB(cfg, oidcConfigRepo)

	moduleScannerJob := jobs.NewModuleScannerJob(&cfg.Scanning, scanRepo, moduleRepo, storageBackend)
	jobRegistry.Register(moduleScannerJob)

	// Initialize and start the scheduled scanner update-check job (no-op when
	// scanning.auto_update.enabled=false). Discovers newer upstream scanner
	// releases, files them into the version-approval workflow, and reconciles
	// approved-but-inactive versions into the running scanner.
	sbvRepo := repositories.NewScannerBinaryVersionRepository(sqlxDB)
	scannerApprovalRepo := repositories.NewVersionApprovalRepository(sqlxDB)
	scannerUpdateJob := jobs.NewScannerUpdateJob(&cfg.Scanning, &cfg.Notifications, &cfg.CVE, sbvRepo, scannerApprovalRepo, oidcConfigRepo, moduleScannerJob, nil, nil)
	scannerUpdateJob.SetEgressGuard(egressGuard)
	jobRegistry.Register(scannerUpdateJob)

	// Initialize the audit log cleanup job (no-op when retention_days=0).
	//
	// THE HOLD TABLE IS VERIFIED ON THE SWEEP'S OWN CONNECTION (#872).
	//
	// auditRepo is built on identityDB, so that is where the DELETE runs and
	// where its NOT EXISTS has to resolve legal_holds. Migration 000057 creates
	// the table in the APP database. Those are the same database in every
	// default deployment and different ones under TFR_IDENTITY_DATABASE_*, and
	// the difference is invisible from either side on its own — which is
	// exactly how a hold gets placed, confirmed in a UI, and swept anyway.
	//
	// So the job is only constructed when the table resolves HERE. If it does
	// not, the sweep does not run at all. Not deleting expired audit rows is
	// untidy and reversible; deleting rows an investigation asked to be
	// preserved is neither, and a compliance control that is documented and
	// absent is worse than one that is absent and known.
	legalHoldTable := "legal_holds"
	var legalHoldHandlers *admin.LegalHoldHandlers
	if err := idstore.VerifyLegalHoldTable(context.Background(), identityDB, legalHoldTable); err != nil {
		slog.Error("audit retention DISABLED: the legal-hold table is not readable on the identity "+
			"connection, so a sweep could not honour holds and will not run",
			"table", legalHoldTable, "error", err,
			"remedy", "run migration 000057 against the database that holds audit_logs; if identity "+
				"lives in a separate database (TFR_IDENTITY_DATABASE_*), the table must be created there")
		legalHoldHandlers = admin.NewUnavailableLegalHoldHandlers(
			"the legal_holds table is not readable on the connection the audit retention sweep runs on")
	} else {
		auditCleanupJob := jobs.NewAuditCleanupJob(&cfg.AuditRetention, auditRepo,
			idstore.WithLegalHolds(legalHoldTable))
		jobRegistry.Register(auditCleanupJob)

		// The API is wired by the SAME condition that wires the sweep, so the
		// two cannot disagree. A deployment where holds are placeable but not
		// honoured is the exact state #872 was filed about: the operator sees a
		// confirmation, the evidence is deleted anyway.
		legalHoldHandlers = admin.NewLegalHoldHandlers(audit.NewLegalHoldStore(identityDB), auditRepo)
	}

	// The transactional audit outbox (issue #766, migration 000052).
	//
	// ON `db`, NOT `identityDB`, AND THAT IS THE WHOLE POINT: the outbox has to
	// share a transaction with the mutation it records, and the privileged
	// mutations it covers run on the registry's own connection (see
	// platformAdminCarrier above). The relay then carries each intent across to
	// audit_logs on identityDB, which is the connection that cannot participate
	// in the mutation's transaction and is why the outbox exists.
	auditOutbox, err := auditoutbox.New(db, audit.OutboxTable)
	if err != nil {
		log.Fatalf("failed to construct the audit outbox: %v", err)
	}
	auditSink, err := auditoutbox.NewTableSink(identityDB, audit.AuditLogTable)
	if err != nil {
		log.Fatalf("failed to construct the audit outbox sink: %v", err)
	}
	// Both ends reported, for the same reason as the carrier above: these are
	// unqualified names placed by each connection's search_path, and an
	// operator who cannot see where intents are written and where they land
	// discovers a misplacement as an audit trail that stopped draining.
	if resolved, vErr := auditOutbox.Verify(context.Background()); vErr != nil {
		slog.Error("audit outbox table did not verify; privileged mutations will refuse to commit until it does",
			"table", audit.OutboxTable, "error", vErr)
	} else {
		slog.Info("audit outbox table verified", "table", resolved)
	}
	if resolved, vErr := auditSink.Verify(context.Background()); vErr != nil {
		slog.Error("audit destination table did not verify; delivered intents will stay in the backlog",
			"table", audit.AuditLogTable, "error", vErr)
	} else {
		slog.Info("audit destination table verified", "table", resolved)
	}
	auditRelay := audit.NewOutboxRelay(auditOutbox, auditSink, auditShipper, auditoutbox.RelayConfig{
		PollInterval:    time.Duration(cfg.AuditRetention.OutboxPollSeconds) * time.Second,
		BatchSize:       cfg.AuditRetention.OutboxBatchSize,
		BacklogWarn:     int64(cfg.AuditRetention.OutboxBacklogWarn),
		RetainDelivered: time.Duration(cfg.AuditRetention.OutboxRetainDeliveredHours) * time.Hour,
	})
	jobRegistry.Register(auditRelay)

	// Get encryption key from environment for OAuth token encryption
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		log.Fatal("ENCRYPTION_KEY environment variable must be set for SCM integration")
	}
	// ENCRYPTION_KEY is used directly as raw AES-256 key bytes (no KDF/hashing), so its
	// real-world entropy determines the actual strength of the cipher. Fail closed by
	// default when the key looks human-typed rather than CSPRNG-generated (issue #560):
	// this key encrypts every stored OAuth/SCM token suite-wide, and warning without
	// enforcing left every installation free to run indefinitely on a guessable key.
	// TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY provides a migration-safe bridge so an
	// existing deployment can restart once to rotate its key instead of being unable
	// to start at all.
	if shouldRejectLowEntropyEncryptionKey([]byte(encryptionKey), allowLowEntropyEncryptionKey()) {
		log.Fatal("ENCRYPTION_KEY has low estimated entropy and may not have been generated with a CSPRNG. Refusing to start (issue #560). Generate one with: openssl rand -hex 16 (see docs/secrets-rotation.md). To roll out this check on an existing deployment while you rotate to a stronger key, set TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY=true temporarily.")
	}
	if crypto.IsLikelyLowEntropySecret([]byte(encryptionKey)) {
		log.Printf("WARNING: ENCRYPTION_KEY has low estimated entropy and may not have been generated with a CSPRNG. Generate one with: openssl rand -hex 16 (TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY override in use -- rotate this key soon)")
	}
	encryptionKeyPrevious := os.Getenv("ENCRYPTION_KEY_PREVIOUS")

	// Initialize token cipher for encrypting OAuth tokens.
	// When ENCRYPTION_KEY_PREVIOUS is set, the cipher supports dual-key
	// decryption for zero-downtime key rotation.
	var tokenCipher *crypto.TokenCipher
	if encryptionKeyPrevious != "" {
		tokenCipher, err = crypto.NewTokenCipherWithPrevious([]byte(encryptionKey), []byte(encryptionKeyPrevious))
		if err != nil {
			log.Fatalf("Failed to initialize dual-key token cipher: %v", err)
		}
		slog.Info("token cipher initialized with previous key for rotation support")
	} else {
		tokenCipher, err = crypto.NewTokenCipher([]byte(encryptionKey))
		if err != nil {
			log.Fatalf("Failed to initialize token cipher: %v", err)
		}
	}

	// Reload persisted notifications config from the database (if present),
	// applying it on top of the YAML/env defaults. Must run after tokenCipher
	// is constructed since the stored SMTP password is encrypted. See
	// reloadNotificationsConfigFromDB.
	reloadNotificationsConfigFromDB(cfg, oidcConfigRepo, tokenCipher)

	// Add middleware
	// middleware.RecoveryMiddleware replaces gin.Recovery(): gin's stock
	// Recovery() only redacts the Authorization header in its panic-recovery
	// request dump, leaving the Cookie/Set-Cookie session token unredacted
	// (issue #663).
	router.Use(middleware.RecoveryMiddleware())
	router.Use(middleware.RequestIDMiddleware())
	router.Use(middleware.MetricsMiddleware())
	router.Use(LoggerMiddleware(cfg))
	router.Use(CORSMiddleware(cfg))
	router.Use(middleware.SecurityHeadersMiddleware(middleware.APISecurityHeadersConfig()))

	// mTLS client-certificate authentication (issue #559 finding [3]). Registered
	// globally and before the per-route Auth/OptionalAuth middleware groups
	// below, so a verified client cert's mapped scopes are already in the Gin
	// context by the time those run — AuthMiddleware treats auth_method=="mtls"
	// as satisfying its "credentials present" check even with no bearer token.
	// Actually verifying and surfacing the client cert requires the TLS server
	// itself to request+verify one (see mtls.BuildServerTLSConfig, wired in
	// cmd/server/main.go); nothing here works over plain HTTP or behind a
	// TLS-terminating ingress.
	if cfg.Security.MTLS.Enabled {
		mtlsProvider, mtlsErr := mtls.NewProvider(cfg.Security.MTLS)
		if mtlsErr != nil {
			log.Fatalf("failed to initialize mTLS provider: %v", mtlsErr)
		}
		// The carrier goes in so an mTLS mapping's `admin` is resolved per
		// request against platform_admins rather than trusted from config
		// (#876). Constructed above at the platformAdminCarrier assignment,
		// which is why this registration sits after it.
		router.Use(mtls.AuthMiddleware(mtlsProvider, platformAdminCarrier))
	}

	// Rate limiters are constructed HERE, ahead of route registration, because
	// registerPublicRoutes now consumes protocolRateLimiter (issue #743). Gin
	// binds a group's middleware at registration time, so a limiter built after
	// this call would never reach the protocol routes.
	// Initialize rate limiters (conditionally, based on config)
	var authRateLimiter, generalRateLimiter, uploadRateLimiter middleware.RateLimiterBackend
	// protocolRateLimiter covers the anonymous Terraform-protocol/OCI/mirror
	// surface registered by registerPublicRoutes (issue #743).
	var protocolRateLimiter middleware.RateLimiterBackend
	var orgRateLimiter middleware.RateLimiterBackend
	if cfg.Security.RateLimiting.Enabled {
		// Build effective configs: use config values when set, otherwise fall back to presets
		generalCfg := middleware.DefaultRateLimitConfig()
		if cfg.Security.RateLimiting.RequestsPerMinute > 0 {
			generalCfg.RequestsPerMinute = cfg.Security.RateLimiting.RequestsPerMinute
		}
		if cfg.Security.RateLimiting.Burst > 0 {
			generalCfg.BurstSize = cfg.Security.RateLimiting.Burst
		}
		authCfg := middleware.AuthRateLimitConfig()
		uploadCfg := middleware.UploadRateLimitConfig()
		protocolCfg := middleware.ProtocolRateLimitConfig()

		if cfg.Redis.Host != "" {
			// Redis-backed rate limiters for HA deployments
			var redisErr error
			generalRateLimiter, redisErr = middleware.NewRedisRateLimiter(&cfg.Redis, generalCfg)
			if redisErr != nil {
				slog.Warn("failed to create Redis rate limiter for general, falling back to in-memory", "error", redisErr)
				generalRateLimiter = middleware.NewRateLimiter(generalCfg)
			}
			authRateLimiter, redisErr = middleware.NewRedisRateLimiter(&cfg.Redis, authCfg)
			if redisErr != nil {
				slog.Warn("failed to create Redis rate limiter for auth, falling back to in-memory", "error", redisErr)
				authRateLimiter = middleware.NewRateLimiter(authCfg)
			}
			uploadRateLimiter, redisErr = middleware.NewRedisRateLimiter(&cfg.Redis, uploadCfg)
			if redisErr != nil {
				slog.Warn("failed to create Redis rate limiter for upload, falling back to in-memory", "error", redisErr)
				uploadRateLimiter = middleware.NewRateLimiter(uploadCfg)
			}
			protocolRateLimiter, redisErr = middleware.NewRedisRateLimiter(&cfg.Redis, protocolCfg)
			if redisErr != nil {
				slog.Warn("failed to create Redis rate limiter for protocol routes, falling back to in-memory", "error", redisErr)
				protocolRateLimiter = middleware.NewRateLimiter(protocolCfg)
			}
			// Per-organization rate limiter (only when configured)
			if cfg.Security.RateLimiting.OrgRequestsPerMinute > 0 {
				orgCfg := middleware.RateLimitConfig{
					RequestsPerMinute: cfg.Security.RateLimiting.OrgRequestsPerMinute,
					BurstSize:         cfg.Security.RateLimiting.OrgBurst,
					CleanupInterval:   5 * time.Minute,
				}
				if orgCfg.BurstSize == 0 {
					orgCfg.BurstSize = orgCfg.RequestsPerMinute / 4
				}
				orgRateLimiter, redisErr = middleware.NewRedisRateLimiter(&cfg.Redis, orgCfg)
				if redisErr != nil {
					slog.Warn("failed to create Redis org rate limiter, falling back to in-memory", "error", redisErr)
					orgRateLimiter = middleware.NewRateLimiter(orgCfg)
				}
			}
			log.Println("Rate limiting enabled with Redis backend")
		} else {
			// In-memory rate limiters (single-instance only)
			slog.Warn("redis.host not configured: rate limiting will use in-memory backend (not suitable for multi-pod HA)")
			generalRateLimiter = middleware.NewRateLimiter(generalCfg)
			authRateLimiter = middleware.NewRateLimiter(authCfg)
			uploadRateLimiter = middleware.NewRateLimiter(uploadCfg)
			protocolRateLimiter = middleware.NewRateLimiter(protocolCfg)
			// Per-organization rate limiter
			if cfg.Security.RateLimiting.OrgRequestsPerMinute > 0 {
				orgCfg := middleware.RateLimitConfig{
					RequestsPerMinute: cfg.Security.RateLimiting.OrgRequestsPerMinute,
					BurstSize:         cfg.Security.RateLimiting.OrgBurst,
					CleanupInterval:   5 * time.Minute,
				}
				if orgCfg.BurstSize == 0 {
					orgCfg.BurstSize = orgCfg.RequestsPerMinute / 4
				}
				orgRateLimiter = middleware.NewRateLimiter(orgCfg)
			}
		}
	}

	// Public + Terraform-protocol routes (issue #565 finding [39]). See registerPublicRoutes.
	registerPublicRoutes(router, &publicRouteDeps{
		cfg:                     cfg,
		db:                      db,
		storageBackend:          storageBackend,
		ociHandler:              ociHandler,
		userRepo:                userRepo,
		apiKeyRepo:              apiKeyRepo,
		orgRepo:                 orgRepo,
		tokenRepo:               tokenRepo,
		userTokenRevocationRepo: userTokenRevocationRepo,
		platformAdminCarrier:    platformAdminCarrier,
		auditRepo:               auditRepo,
		pullThroughSvc:          pullThroughSvc,
		tfBinariesHandler:       tfBinariesHandler,
		protocolRateLimiter:     protocolRateLimiter,
	})

	// Initialize admin handlers
	// Select OIDC state store backend: Redis for HA, in-memory for single-instance.
	var oidcStateStore auth.StateStore
	if cfg.Redis.Host != "" {
		redisStore, storeErr := auth.NewRedisStateStore(&cfg.Redis)
		if storeErr != nil {
			slog.Warn("failed to create Redis OIDC state store, falling back to in-memory", "error", storeErr)
			oidcStateStore = auth.NewMemoryStateStore(5 * time.Minute)
		} else {
			oidcStateStore = redisStore
		}
	} else {
		oidcStateStore = auth.NewMemoryStateStore(5 * time.Minute)
	}

	// credSweeper invalidates BOTH credential families that snapshot a
	// principal's derived authority (JWT sessions via the revoke-all watermark,
	// API keys via the api_keys row) whenever a lifecycle event reduces that
	// authority. userTokenRevocationRepo lives on the registry connection and
	// apiKeyRepo on the identity connection, so the two halves cannot be
	// constructed from a single handle -- it is built once here and injected
	// wherever an authority-reducing handler lives (issues #732, #736).
	credSweeper := credlifecycle.NewSweeper(userTokenRevocationRepo, apiKeyRepo)

	var authHandlers *admin.AuthHandlers
	authHandlers, err = admin.NewAuthHandlers(cfg, identityDB, oidcConfigRepo, tokenRepo, oidcStateStore,
		admin.WithSAMLEgressGuard(egressGuard), admin.WithCredentialSweeper(credSweeper),
		admin.WithAdminFloor(adminFloor))
	if err != nil {
		log.Fatalf("Failed to initialize auth handlers: %v", err)
	}

	// Load OIDC configuration persisted by the setup wizard from the database
	// (takes precedence over static config-file settings). See
	// applyPersistedOIDCProvider.
	applyPersistedOIDCProvider(authHandlers, oidcConfigRepo, tokenCipher)

	// Identity-backed admin handlers use the identity connection (their internal
	// identity repos / raw identity SQL then follow the identity schema). The org
	// handler's namespace cascade and the stats handler's feature-table counts
	// fall back to public via the identity connection's search_path.
	apiKeyHandlers := admin.NewAPIKeyHandlers(cfg, identityDB)
	userHandlers := admin.NewUserHandlers(cfg, identityDB, admin.WithUserCredentialSweeper(credSweeper),
		admin.WithUserAdminFloor(adminFloor, platformAdminCarrier, auditOutbox),
		// scmRepo, deliberately: it is built on the registry connection above,
		// and scm_oauth_tokens stays in the registry's schema at cutover.
		admin.WithUserSCMTokens(scmRepo))
	orgHandlers := admin.NewOrganizationHandlers(cfg, identityDB, nsClaimRepo, userTokenRevocationRepo).
		WithAdminFloor(adminFloor).
		// scmRepo and mirrorRepo, deliberately: both are built on the REGISTRY
		// connection above, and scm_providers / mirror_configurations stay in
		// the registry's schema at the identity cutover. Organization deletion
		// refuses while either still holds a row for the organization -- the
		// invariant migration 000056 could not keep in SQL (issues #883, #899).
		WithOrgIntegrationGuards(scmRepo, mirrorRepo)
	statsHandlers := admin.NewStatsHandler(identitySqlxDB, &cfg.Scanning).WithOrgRepo(orgRepo)
	mirrorHandlers := admin.NewMirrorHandler(mirrorRepo, orgRepo, providerRepo)
	mirrorHandlers.SetSyncJob(mirrorSyncJob) // Connect sync job for manual triggers
	mirrorHandlers.SetEgressGuard(egressGuard)

	// Initialize Terraform binary mirror admin handler
	tfMirrorAdminHandler := admin.NewTerraformMirrorHandler(tfMirrorRepo)
	tfMirrorAdminHandler.SetSyncJob(tfMirrorSyncJob)
	tfMirrorAdminHandler.SetStorageBackend(storageBackend) // delete stored binaries when a version is removed
	tfMirrorAdminHandler.SetEgressGuard(egressGuard)
	releasesGPGKeysAdminHandler := admin.NewReleasesGPGKeysHandler(releasesKeyRepo, tfMirrorRepo, cfg.ReleasesGPGKeys)
	versionApprovalHandler := admin.NewVersionApprovalHandler(repositories.NewVersionApprovalRepository(sqlxDB)).
		WithOrgRepo(orgRepo)
	providerAdminHandlers := admin.NewProviderAdminHandlers(db, storageBackend, cfg)
	moduleAdminHandlers := admin.NewModuleAdminHandlers(db, storageBackend, cfg).
		WithModuleDocs(moduleDocsRepo).
		WithScanQueue(scanRepo)

	// GDPR data-subject handlers (Article 15/17/20). Registered under
	// /api/v1/admin/users/:id/{export,erase} below.
	userSvc := services.NewUserService(identityDB).WithCredentialSweeper(credSweeper).
		WithAdminFloor(adminFloor, platformAdminCarrier, auditOutbox)
	gdprHandlers := admin.NewGDPRHandlers(userSvc)

	// Role-template CRUD follows the identity schema; mirror methods stay public.
	rbacRepo := repositories.NewRBACRepositoryWithIdentity(sqlxDB, identitySqlxDB)
	rbacHandlers := admin.NewRBACHandlers(rbacRepo, userTokenRevocationRepo, apiKeyRepo).
		WithNotifications(&cfg.Notifications, &cfg.CVE).
		WithOrgRepo(orgRepo).
		WithMirrorRepo(mirrorRepo)

	// Initialize audit log handlers
	auditLogHandlers := admin.NewAuditLogHandlers(identityDB)

	// Platform-admin management (issue #766, PR 2). Spans both connections by
	// construction: the carrier is on the registry's own connection (see
	// platformAdminCarrier above, and migration 000051 for why it carries no FK),
	// while the users it names live on the identity connection. Its audit trail
	// is written to the outbox beside the carrier — same connection, same
	// transaction — and relayed to audit_logs on identityDB afterwards, which
	// is what stops a grant from committing unrecorded (migration 000052).
	platformAdminHandlers := admin.NewPlatformAdminHandlers(platformAdminCarrier, userRepo, auditOutbox).
		WithAdminFloor(adminFloor)

	// Shared app-credential minter (Entra app / GitHub App) for providers opted
	// into an app auth mode; scmRepo provides the token-cache store. Uses the
	// shared egress guard for parity with the other SCM outbound paths (#676).
	sharedMinter := appcreds.NewMinterWithGuard(tokenCipher, scmRepo, egressGuard)

	// Initialize SCM publisher service (needed by scmLinkingHandler)
	scmPublisher := services.NewSCMPublisher(scmRepo, moduleRepo, storageBackend, tokenCipher).
		WithScanQueue(scanRepo, &cfg.Scanning).
		WithModuleDocs(moduleDocsRepo).
		WithSharedMinter(sharedMinter)

	// Initialize the webhook retry job (no-op when max_retries=0)
	webhookRetryJob := jobs.NewWebhookRetryJob(&cfg.Webhooks, scmRepo, moduleRepo, scmPublisher, tokenCipher)
	jobRegistry.Register(webhookRetryJob)

	// Initialize the CVE polling job (no-op when cve.enabled=false)
	cveRepo := repositories.NewCVERepository(db)
	cvePollJob := jobs.NewCVEPollJob(cveRepo, auditRepo, &cfg.Scanning, &cfg.CVE, &cfg.Notifications)
	cvePollJob.SetEgressGuard(egressGuard)
	jobRegistry.Register(cvePollJob)

	// Initialize SCM handlers with the already-created repositories and token cipher
	scmProviderHandlers := admin.NewSCMProviderHandlers(cfg, scmRepo, orgRepo, tokenCipher).WithMinter(sharedMinter).WithEgressGuard(egressGuard)
	// The SCM connector flow shares the login flow's state store: its callback is
	// unauthenticated, so its `state` must be an unguessable, server-side,
	// single-use nonce exactly like the OIDC login state.
	scmOAuthHandlers := admin.NewSCMOAuthHandlers(cfg, scmRepo, userRepo, tokenCipher).
		WithMinter(sharedMinter).
		WithStateStore(oidcStateStore)
	scmLinkingHandler := modules.NewSCMLinkingHandler(scmRepo, moduleRepo, tokenCipher, cfg.Server.BaseURL, scmPublisher).WithMinter(sharedMinter)

	// Initialize storage configuration handlers
	storageHandlers := admin.NewStorageHandlers(cfg, storageConfigRepo, tokenCipher)

	// Initialize notifications configuration handlers
	notificationsHandler := admin.NewNotificationsHandler(&cfg.Notifications, oidcConfigRepo, tokenCipher, &cfg.CVE)

	// Notification channels: additional delivery destinations (webhook, Slack,
	// Microsoft Teams, or an ad-hoc email recipient list) for the
	// module_published, approval_pending, cve_detected, and
	// scanner_update_available events, alongside the shared SMTP recipients
	// list above. Wire the notifier into every trigger that fans those events
	// out so channels observe them in addition to the direct-recipients email.
	// The notifier and the channel handlers both take identityGuard so a
	// webhook/Slack/Teams target URL is subject to the same SSRF egress policy
	// as every other outbound client (validated at save, enforced at dial).
	//
	// identityTokenCipher/identityGuard are separate instances (built from the
	// same key material / allow-list as tokenCipher/egressGuard above) of the
	// shared identity/crypto and identity/httpsafe types the shared
	// identity/notify package requires — see the cross-app notification
	// parity effort. tokenCipher/egressGuard remain registry's own types for
	// every other existing use (SCM tokens, storage keys, mirror sync, ...).
	identityTokenCipher, err := buildIdentityTokenCipher(encryptionKey, encryptionKeyPrevious)
	if err != nil {
		log.Fatalf("Failed to initialize shared token cipher: %v", err)
	}
	identityGuard, err := identityhttpsafe.NewGuard(cfg.Security.Egress.Allowlist)
	if err != nil {
		log.Fatalf("invalid security.egress.allowlist: %v", err)
	}
	notificationsSMTPConfig := func() identitymailer.Config {
		return identitymailer.Config{
			Host:     cfg.Notifications.SMTP.Host,
			Port:     cfg.Notifications.SMTP.Port,
			From:     cfg.Notifications.SMTP.From,
			Username: cfg.Notifications.SMTP.Username,
			Password: cfg.Notifications.SMTP.Password,
			// See notificationsExpiryConfig above: one mapping helper, not a
			// hand-written conditional per call site.
			TLSMode: identitymailer.TLSModeForUseTLS(cfg.Notifications.SMTP.UseTLS),
		}
	}
	notificationChannelRepo := repositories.NewNotificationChannelRepository(db)
	notifierOpts := identitynotify.Options{Source: "terraform-registry", TestMessage: "This is a test from the Terraform Registry."}
	notifier := notify.NewNotifier(notificationChannelRepo, notificationsSMTPConfig, identityTokenCipher, identityGuard, notifierOpts)
	notificationChannelHandlers := admin.NewNotificationChannelHandlers(notificationChannelRepo, notifier, identityTokenCipher, identityGuard)
	cvePollJob.SetNotifier(notifier)
	scannerUpdateJob.SetNotifier(notifier)
	rbacHandlers.WithNotifier(notifier)

	// Initialize OIDC admin configuration handlers
	oidcAdminHandlers := admin.NewOIDCConfigAdminHandlers(oidcConfigRepo)

	// Initialize setup wizard handlers
	setupHandlers := setup.NewHandlers(
		cfg, tokenCipher, oidcConfigRepo, storageConfigRepo, userRepo, authHandlers,
	).WithScannerJob(moduleScannerJob).WithEgressGuard(egressGuard).
		WithPlatformAdminCarrier(platformAdminCarrier, auditOutbox)

	// Initialize policy engine (no-op when disabled).
	policyEngineCfg := policy.Config{
		Enabled:               cfg.Policy.Enabled,
		Mode:                  cfg.Policy.Mode,
		BundleURL:             cfg.Policy.BundleURL,
		BundleSHA256:          cfg.Policy.BundleSHA256,
		BundleRefreshInterval: cfg.Policy.BundleRefreshInterval,
	}
	policyEngine, err := policy.NewPolicyEngineWithGuard(policyEngineCfg, egressGuard)
	if err != nil {
		log.Fatalf("failed to initialize policy engine: %v", err)
	}
	policyAdminHandler := admin.NewPolicyHandler(policyEngine, cfg.Policy)

	// Initialize SCM webhook handler
	// orgRepo, deliberately on the IDENTITY connection: the webhook route is
	// unauthenticated and acts on scm_providers.webhook_secret on the row's own
	// authority, so it has to be able to ask whether the row's organization is
	// still there. Migration 000056 dropped the foreign key that used to make
	// the question unaskable (issues #883, #899).
	scmWebhookHandler := webhooks.NewSCMWebhookHandler(scmRepo, scmPublisher, tokenCipher).
		WithOrganizationExistence(orgRepo)
	approvalWebhookHandler := webhooks.NewApprovalHandler(rbacRepo)

	// Build per-principal override rate limiters (if configured)
	var principalOverrides *middleware.PrincipalOverrideLimiters
	if len(cfg.Security.RateLimiting.PrincipalOverrides) > 0 {
		principalOverrides = middleware.NewPrincipalOverrideLimiters(cfg.Security.RateLimiting.PrincipalOverrides)
		slog.Info("per-principal rate limit overrides configured", "count", len(cfg.Security.RateLimiting.PrincipalOverrides))
	}

	// Public + admin API routes (issue #565 finding [39]). See registerAPIV1Routes.
	registerAPIV1Routes(router, &apiV1RouteDeps{
		cfg:                         cfg,
		db:                          db,
		identityDB:                  identityDB,
		storageBackend:              storageBackend,
		sqlxDB:                      sqlxDB,
		oidcConfigRepo:              oidcConfigRepo,
		setupHandlers:               setupHandlers,
		authRateLimiter:             authRateLimiter,
		generalRateLimiter:          generalRateLimiter,
		uploadRateLimiter:           uploadRateLimiter,
		orgRateLimiter:              orgRateLimiter,
		principalOverrides:          principalOverrides,
		authHandlers:                authHandlers,
		userRepo:                    userRepo,
		apiKeyRepo:                  apiKeyRepo,
		orgRepo:                     orgRepo,
		tokenRepo:                   tokenRepo,
		userTokenRevocationRepo:     userTokenRevocationRepo,
		platformAdminCarrier:        platformAdminCarrier,
		credSweeper:                 credSweeper,
		adminFloor:                  adminFloor,
		moduleAdminHandlers:         moduleAdminHandlers,
		providerAdminHandlers:       providerAdminHandlers,
		auditRepo:                   auditRepo,
		auditShipper:                auditShipper,
		nsAuthz:                     nsAuthz,
		scmRepo:                     scmRepo,
		mirrorRepo:                  mirrorRepo,
		rbacRepo:                    rbacRepo,
		scanRepo:                    scanRepo,
		moduleDocsRepo:              moduleDocsRepo,
		policyEngine:                policyEngine,
		sbvRepo:                     sbvRepo,
		scannerApprovalRepo:         scannerApprovalRepo,
		scannerUpdateJob:            scannerUpdateJob,
		notificationsHandler:        notificationsHandler,
		notificationChannelHandlers: notificationChannelHandlers,
		notifier:                    notifier,
		apiKeyHandlers:              apiKeyHandlers,
		userHandlers:                userHandlers,
		gdprHandlers:                gdprHandlers,
		orgHandlers:                 orgHandlers,
		scmProviderHandlers:         scmProviderHandlers,
		scmOAuthHandlers:            scmOAuthHandlers,
		scmLinkingHandler:           scmLinkingHandler,
		mirrorHandlers:              mirrorHandlers,
		tfMirrorAdminHandler:        tfMirrorAdminHandler,
		releasesGPGKeysAdminHandler: releasesGPGKeysAdminHandler,
		rbacHandlers:                rbacHandlers,
		platformAdminHandlers:       platformAdminHandlers,
		legalHoldHandlers:           legalHoldHandlers,
		versionApprovalHandler:      versionApprovalHandler,
		storageHandlers:             storageHandlers,
		storageConfigRepo:           storageConfigRepo,
		moduleRepo:                  moduleRepo,
		providerRepo:                providerRepo,
		tokenCipher:                 tokenCipher,
		oidcAdminHandlers:           oidcAdminHandlers,
		auditLogHandlers:            auditLogHandlers,
		policyAdminHandler:          policyAdminHandler,
		cvePollJob:                  cvePollJob,
		statsHandlers:               statsHandlers,
		scmWebhookHandler:           scmWebhookHandler,
		approvalWebhookHandler:      approvalWebhookHandler,
		egressGuard:                 egressGuard,
	})

	// Start every registered background job now that all wiring is complete.
	// Each runs in its own goroutine (Registry.StartAll); context.Background()
	// means they exit only via BackgroundServices.Shutdown (Stop), matching the
	// prior per-job `go job.Start(context.Background())` behavior.
	jobRegistry.StartAll(context.Background())

	bg := &BackgroundServices{
		jobs:               jobRegistry,
		rateLimiters:       collectRateLimiterBackends(authRateLimiter, generalRateLimiter, uploadRateLimiter, orgRateLimiter),
		principalOverrides: principalOverrides,
		auditShipper:       auditShipper,
	}

	return router, bg
}

// shouldRejectLowEntropyEncryptionKey reports whether NewRouter should refuse
// to start given ENCRYPTION_KEY's estimated entropy. Extracted from the
// entropy check inline in NewRouter so the fail-closed decision (issue #560)
// can be unit tested without exercising log.Fatal.
func shouldRejectLowEntropyEncryptionKey(encryptionKey []byte, overrideAllowed bool) bool {
	return crypto.IsLikelyLowEntropySecret(encryptionKey) && !overrideAllowed
}

// allowLowEntropyEncryptionKey reports whether an operator has explicitly
// opted out of the fail-closed low-entropy ENCRYPTION_KEY check (issue #560).
// Off by default; enable with TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY=true only
// as a temporary bridge while rotating an existing deployment to a
// CSPRNG-generated key.
func allowLowEntropyEncryptionKey() bool {
	return os.Getenv("TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY") == "true"
}

// @Summary      Health check
// @Description  Returns the health status of the service, including database connectivity.
// @Tags         System
// @Produce      json
// @Success      200  {object}  api.HealthResponse
// @Failure      503  {object}  api.HealthResponse
// @Router       /health [get]
// healthCheckHandler returns the health status of the service
func healthCheckHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check database connection
		if err := db.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
				"error":  "database connection failed",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":     "healthy",
			"time":       time.Now().UTC().Format(time.RFC3339),
			"version":    AppVersion,
			"build_date": AppBuildDate,
		})
	}
}

// @Summary      Readiness check
// @Description  Returns whether the service is ready to accept traffic. Checks database connectivity.
// @Tags         System
// @Produce      json
// @Success      200  {object}  api.ReadinessResponse
// @Failure      503  {object}  api.ReadinessResponse
// @Router       /ready [get]
// readinessHandler returns the readiness status of the service.
// Unlike the liveness probe (/health), this also checks the storage backend so
// that a Kubernetes readiness gate fails when uploads/downloads would error.
func readinessHandler(db *sql.DB, storageBackend storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		checks := gin.H{}

		// Check database connection
		if err := db.Ping(); err != nil {
			checks["database"] = "unhealthy"
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"ready":  false,
				"checks": checks,
				"error":  "database not ready",
			})
			return
		}
		checks["database"] = "healthy"

		// Check storage backend — probe with a known-absent sentinel path.
		// Exists() exercises authentication and network connectivity without
		// creating any state.
		if _, err := storageBackend.Exists(c.Request.Context(), ".readiness-probe"); err != nil {
			checks["storage"] = "unhealthy"
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"ready":  false,
				"checks": checks,
				"error":  "storage backend not ready",
			})
			return
		}
		checks["storage"] = "healthy"

		c.JSON(http.StatusOK, gin.H{
			"ready":  true,
			"checks": checks,
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// @Summary      Terraform service discovery
// @Description  Implements the Terraform service discovery protocol. Returns the base URLs for the Module Registry and Provider Registry endpoints.
// @Tags         System
// @Produce      json
// @Success      200  {object}  api.ServiceDiscoveryResponse
// @Router       /.well-known/terraform.json [get]
// serviceDiscoveryHandler implements Terraform service discovery.
//
// The endpoint URLs are built from GetPublicURL() (public_url, falling back to
// base_url) rather than base_url directly. This is the host Terraform resolves
// "source = HOST/ns/name/system" against and that the State Manager captures for
// the suite "Consumed by" join, so it must match the join key the suite proxy
// emits (also GetPublicURL-derived). In the default deploy public_url is empty
// and this is byte-for-byte identical to the previous base_url output.
func serviceDiscoveryHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		publicURL := cfg.Server.GetPublicURL()
		c.JSON(http.StatusOK, gin.H{
			"modules.v1":   publicURL + "/v1/modules/",
			"providers.v1": publicURL + "/v1/providers/",
			"oci.v1":       publicURL + "/v2/",
		})
	}
}

// @Summary      API version
// @Description  Returns the current API version and supported protocol versions.
// @Tags         System
// @Produce      json
// @Success      200  {object}  api.VersionResponse
// @Router       /version [get]
// versionHandler returns the API version
func versionHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":          AppVersion,
			"build_date":       AppBuildDate,
			"api_version":      "v1",
			"crypto_mode":      AppCryptoMode,
			"default_language": cfg.Server.DefaultLanguage,
			"protocols": gin.H{
				"modules":   "v1",
				"providers": "v1",
				"mirror":    "v1",
			},
			"capabilities": gin.H{
				"oci": true,
			},
		})
	}
}

// LoggerMiddleware provides structured logging
func LoggerMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := middleware.RedactSensitivePath(c.Request.URL.Path)
		query := middleware.RedactSensitiveQuery(c.Request.URL.RawQuery)

		c.Next()

		latency := time.Since(start)

		// Log the request
		if cfg.Logging.Format == "json" {
			logJSON(c, latency, path, query)
		} else {
			logText(c, latency, path, query)
		}
	}
}

// logJSON logs a request as a JSON-structured slog record.
func logJSON(c *gin.Context, latency time.Duration, path, query string) {
	requestID, _ := c.Get(middleware.RequestIDKey)
	slog.LogAttrs(
		c.Request.Context(),
		slog.LevelInfo,
		"http request",
		slog.String("method", c.Request.Method),
		slog.String("path", path),
		slog.String("query", query),
		slog.Int("status", c.Writer.Status()),
		slog.Int("size", c.Writer.Size()),
		slog.Duration("latency", latency),
		slog.String("ip", c.ClientIP()),
		slog.String("request_id", fmt.Sprintf("%v", requestID)),
		slog.String("user_agent", c.Request.UserAgent()),
	)
}

// logText logs a request as a human-readable slog text record.
func logText(c *gin.Context, latency time.Duration, path, query string) {
	// reuse the same structured output; slog will emit text format when the global
	// handler is a TextHandler (configured in telemetry.SetupLogger).
	logJSON(c, latency, path, query)
}

// CORSMiddleware handles CORS
func CORSMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check if origin is allowed and track which rule matched. Scan for an
		// exact origin match first, and only fall back to the wildcard rule if
		// none is found — so credentialed-vs-not behavior for a given origin
		// does not depend on where "*" sits in the configured list (issue #695).
		allowed := false
		matchedWildcard := false
		hasWildcard := false
		for _, allowedOrigin := range cfg.Security.CORS.AllowedOrigins {
			if allowedOrigin == "*" {
				hasWildcard = true
				continue
			}
			if allowedOrigin == origin {
				allowed = true
				matchedWildcard = false
				break
			}
		}
		if !allowed && hasWildcard {
			allowed = true
			matchedWildcard = true
		}

		if allowed {
			if origin == "" {
				// No Origin header — return wildcard, no credentials
				c.Header("Access-Control-Allow-Origin", "*")
			} else if matchedWildcard {
				// Wildcard config but specific origin present —
				// reflect origin WITHOUT credentials (safer than true wildcard)
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			} else {
				// Specific origin match — credentials allowed
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Credentials", "true")
				c.Header("Vary", "Origin")
			}
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With")
			c.Header("Access-Control-Max-Age", "3600")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
