package api

import (
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sethbacon/terraform-suite-identity/identity/platformadmin"
	"github.com/terraform-registry/terraform-registry/internal/audit"
	"github.com/terraform-registry/terraform-registry/internal/auth/mtls"
	"github.com/terraform-registry/terraform-registry/internal/auth/oidc"
	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/crypto"
	"github.com/terraform-registry/terraform-registry/internal/httpsafe"
	"github.com/terraform-registry/terraform-registry/internal/middleware"
	"github.com/terraform-registry/terraform-registry/internal/scm"
)

// Wiring phases lifted out of NewRouter (issue #565 finding [39]), which mixed
// dependency construction, key material, job orchestration and ~150 route
// registrations in one function. Route registration already moved to
// router_routes.go and the persisted-config reloads to router_startup.go; this
// file holds the two remaining blocks that construct something self-contained
// from configuration alone, so each can be read -- and changed -- without
// reading the startup order around it.

// encryptionKeys is the ENCRYPTION_KEY material, already validated. It carries
// the raw strings as well as knowing how to build a cipher because two
// different ciphers are built from the same pair: registry's own
// crypto.TokenCipher, and the shared identity one via buildIdentityTokenCipher.
type encryptionKeys struct {
	current  string
	previous string
}

// encryptionKeysFromEnv reads and validates the key material, or refuses to
// start. It does not return an error: every failure here is a configuration
// fault that must stop the process, and NewRouter's callers cannot do anything
// useful with one.
func encryptionKeysFromEnv() encryptionKeys {
	current := os.Getenv("ENCRYPTION_KEY")
	if current == "" {
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
	if shouldRejectLowEntropyEncryptionKey([]byte(current), allowLowEntropyEncryptionKey()) {
		log.Fatal("ENCRYPTION_KEY has low estimated entropy and may not have been generated with a CSPRNG. Refusing to start (issue #560). Generate one with: openssl rand -base64 32. Set TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY=true to start once and rotate.")
	}
	if crypto.IsLikelyLowEntropySecret([]byte(current)) {
		log.Printf("WARNING: ENCRYPTION_KEY has low estimated entropy and may not have been generated with a CSPRNG. Generate one with: openssl rand -base64 32")
	}
	return encryptionKeys{current: current, previous: os.Getenv("ENCRYPTION_KEY_PREVIOUS")}
}

// newTokenCipher builds registry's own token cipher. When
// ENCRYPTION_KEY_PREVIOUS is set the cipher supports dual-key decryption for
// zero-downtime key rotation.
func (k encryptionKeys) newTokenCipher() *crypto.TokenCipher {
	if k.previous != "" {
		cipher, err := crypto.NewTokenCipherWithPrevious([]byte(k.current), []byte(k.previous))
		if err != nil {
			log.Fatalf("Failed to initialize dual-key token cipher: %v", err)
		}
		slog.Info("token cipher initialized with previous key for rotation support")
		return cipher
	}
	cipher, err := crypto.NewTokenCipher([]byte(k.current))
	if err != nil {
		log.Fatalf("Failed to initialize token cipher: %v", err)
	}
	return cipher
}

// rateLimiters is the set of backends route registration selects between. Each
// is nil when rate limiting is disabled, which the middleware treats as "no
// limit" -- so the zero value is the disabled configuration rather than a bug.
type rateLimiters struct {
	auth     middleware.RateLimiterBackend
	general  middleware.RateLimiterBackend
	upload   middleware.RateLimiterBackend
	protocol middleware.RateLimiterBackend
	org      middleware.RateLimiterBackend
}

// newRateLimiters constructs them ahead of route registration, because the
// route groups take a backend rather than building their own. A Redis failure
// falls back to the in-memory backend and says so, rather than starting with no
// limit at all.
func newRateLimiters(cfg *config.Config) rateLimiters {
	var r rateLimiters
	if !cfg.Security.RateLimiting.Enabled {
		return r
	}

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

	orgCfg, orgWanted := orgRateLimitConfig(cfg)

	if cfg.Redis.Host == "" {
		slog.Warn("redis.host not configured: rate limiting will use in-memory backend (not suitable for multi-pod HA)")
		r.general = middleware.NewRateLimiter(generalCfg)
		r.auth = middleware.NewRateLimiter(authCfg)
		r.upload = middleware.NewRateLimiter(uploadCfg)
		r.protocol = middleware.NewRateLimiter(protocolCfg)
		if orgWanted {
			r.org = middleware.NewRateLimiter(orgCfg)
		}
		return r
	}

	r.general = redisLimiterOrMemory(cfg, generalCfg, "general")
	r.auth = redisLimiterOrMemory(cfg, authCfg, "auth")
	r.upload = redisLimiterOrMemory(cfg, uploadCfg, "upload")
	r.protocol = redisLimiterOrMemory(cfg, protocolCfg, "protocol routes")
	if orgWanted {
		r.org = redisLimiterOrMemory(cfg, orgCfg, "org")
	}
	log.Println("Rate limiting enabled with Redis backend")
	return r
}

// orgRateLimitConfig reports the per-organization limit and whether one is
// configured at all. The burst default was duplicated in both backend branches.
func orgRateLimitConfig(cfg *config.Config) (middleware.RateLimitConfig, bool) {
	if cfg.Security.RateLimiting.OrgRequestsPerMinute <= 0 {
		return middleware.RateLimitConfig{}, false
	}
	orgCfg := middleware.RateLimitConfig{
		RequestsPerMinute: cfg.Security.RateLimiting.OrgRequestsPerMinute,
		BurstSize:         cfg.Security.RateLimiting.OrgBurst,
		CleanupInterval:   5 * time.Minute,
	}
	if orgCfg.BurstSize == 0 {
		orgCfg.BurstSize = orgCfg.RequestsPerMinute / 4
	}
	return orgCfg, true
}

// redisLimiterOrMemory keeps the fallback identical for every limiter: the
// five call sites above each repeated the same warn-and-degrade block, which is
// exactly where one of them would eventually be left silently returning nil.
func redisLimiterOrMemory(cfg *config.Config, limitCfg middleware.RateLimitConfig, name string) middleware.RateLimiterBackend {
	backend, err := middleware.NewRedisRateLimiter(&cfg.Redis, limitCfg)
	if err != nil {
		slog.Warn("failed to create Redis rate limiter, falling back to in-memory", "limiter", name, "error", err)
		return middleware.NewRateLimiter(limitCfg)
	}
	return backend
}

// installGlobalMiddleware puts the router-wide middleware chain in place.
//
// Extracted from NewRouter for issue #565 finding [39]. ORDER IS THE WHOLE
// POINT of this phase, which is why it moved as one piece rather than being
// spread across the callers that supply its arguments: recovery has to wrap
// everything, and the mTLS middleware has to be registered before the per-route
// Auth/OptionalAuth groups so a verified client certificate's scopes are
// already in the Gin context when those run.
func installGlobalMiddleware(router *gin.Engine, cfg *config.Config, platformAdminCarrier *platformadmin.Carrier) {
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
}

// egressAndAuditShipping configures every outbound egress policy this process
// enforces, and builds the audit external-shipping subsystem that depends on
// the resulting guard.
//
// Extracted from NewRouter for issue #565 finding [39]. The three egress calls
// travel together because they configure the SAME allow-list in three places --
// this router's own guard, package scm's connector client, and the shared
// identity module's OIDC client -- and the failure of forgetting one is an
// internal IdP or SCM host that is denied at construction with no obvious link
// back to security.egress.allowlist. Audit shipping is here rather than with
// the other subsystems because it consumes the guard these calls produce.
//
// Fatal on a bad allow-list: Config.Validate already parsed it at Load(), so a
// parse error here means cfg was built without going through config.Load.
func egressAndAuditShipping(cfg *config.Config) (*httpsafe.Guard, audit.Shipper) {
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

	return egressGuard, auditShipper
}
